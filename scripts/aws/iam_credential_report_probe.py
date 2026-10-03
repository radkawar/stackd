#!/usr/bin/env python3
"""Capture IAM credential reports while discarding unrelated account rows.

Run with AWS CLI credentials. --inspect-only reads the existing artifact without
creating anything. A full run creates uniquely owned users only when a fresh
report can include them; it never waits four hours or changes account settings.
Raw responses, passwords, access-key secrets, certificate keys and MFA seeds
remain in process memory or automatically removed temporary directories.
"""

import argparse
import base64
import csv
import datetime
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

from aws_cli import run as run_cli, result as cli_result, raw_xml


ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / '.stackd/probes/iam/credential_report.json'
COMMON = ["--endpoint-url", "https://iam.amazonaws.com", "--region", "us-east-1",
          "--no-paginate"]
DOCUMENTATION = [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html",
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html",
]


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def call(action, parameters=None, debug=False, environment=None):
    options = [*COMMON, *(["--debug"] if debug else [])]
    process = run_cli("iam", action, parameters or {}, environment, options=options, timeout=60)
    return cli_result(process, debug=debug), raw_xml(process) if debug else None


class Probe:
    def __init__(self):
        self.prefix = "stackd-credential-" + uuid.uuid4().hex[:10]
        self.started = stamp()
        self.account, self.observations, self.cleanup, self.owned = "", [], [], []
        self.setup, self.limitations = [], []
        self.identifiers = {}
        self.first_content, self.first_generated = None, None
        self.complete = False
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")

    def normalize(self, value):
        if isinstance(value, dict):
            return {key: self.normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, str):
            for actual, replacement in self.identifiers.items():
                value = value.replace(actual, replacement)
            value = value.replace(self.prefix, "stackd-credential-fixture")
            if self.account:
                value = value.replace(self.account, "123456789012")
        return value

    def require(self, action, parameters=None):
        result, _ = call(action, parameters)
        if result["code"] != "Success":
            raise RuntimeError(action + ": " + result["code"] + ": " + result.get("message", ""))
        return result["output"]

    def own(self, kind, identifier, **details):
        self.owned.append({"kind": kind, "id": identifier, **details})
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.journal.write_text(json.dumps({"prefix": self.prefix, "owned": self.owned}, indent=2) + "\n")

    def get(self, case):
        result, raw = call("get-credential-report", debug=True)
        row = {"case": case, "operation": "GetCredentialReport", "observed_at": stamp(),
               "code": result["code"], "http_status": result.get("http_status")}
        if result["code"] == "Success":
            output = result["output"]
            content = base64.b64decode(output["Content"], validate=True)
            text = content.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text, newline=""))
            rows = list(reader)
            row.update({"generated_time": output["GeneratedTime"], "report_format": output["ReportFormat"],
                        "output_fields": sorted(output), "header": reader.fieldnames,
                        "csv_header_line": text.splitlines()[0], "row_count": len(rows),
                        "csv_ends_with_newline": text.endswith("\n"), "csv_uses_crlf": "\r\n" in text,
                        "owned_rows": [item for item in rows if item["user"].startswith(self.prefix)]})
            root = next(((index, item) for index, item in enumerate(rows) if item["user"] == "<root_account>"), None)
            if root:
                row["root_row_index"] = root[0]
                row["root_field_shapes"] = {
                    key: "<boolean>" if value in ("true", "false", "TRUE", "FALSE")
                    else "<iso8601>" if re.fullmatch(r"\d{4}-\d\d-\d\dT.*", value)
                    else "<root_arn>" if key == "arn"
                    else value if value in ("<root_account>", "N/A", "no_information", "not_supported", "")
                    else "<nonempty_text>"
                    for key, value in root[1].items()}
            row["owned_row_order"] = [item["user"] for item in rows if item["user"].startswith(self.prefix)]
            row["nonroot_names_lexicographically_sorted"] = [item["user"] for item in rows if item["user"] != "<root_account>"] == sorted(item["user"] for item in rows if item["user"] != "<root_account>")
            row["nonroot_arns_lexicographically_sorted"] = [item["arn"] for item in rows if item["user"] != "<root_account>"] == sorted(item["arn"] for item in rows if item["user"] != "<root_account>")
            names = [item["user"] for item in rows if item["user"] != "<root_account>"]
            row["nonroot_names_case_insensitively_sorted"] = names == sorted(names, key=str.casefold)
            if self.first_content is None:
                self.first_content, self.first_generated = content, output["GeneratedTime"]
            else:
                row["content_identical_to_first_success"] = content == self.first_content
                row["generated_time_identical_to_first_success"] = output["GeneratedTime"] == self.first_generated
            row["wire_content_base64_matches_cli"] = False
            if raw:
                xml = ET.fromstring(raw)
                for element in xml.iter():
                    element.tag = element.tag.rsplit("}", 1)[-1]
                wire_content = xml.findtext("GetCredentialReportResult/Content")
                row["wire_content_base64_matches_cli"] = wire_content == output["Content"] and base64.b64decode(wire_content, validate=True) == content
                row["wire_generated_time"] = xml.findtext("GetCredentialReportResult/GeneratedTime")
        else:
            row["message"] = result.get("message", "")
        self.observations.append(self.normalize(row))
        self.write(False)
        print(case, result["code"], row.get("generated_time", ""), flush=True)
        return result

    def generate(self, case):
        result, _ = call("generate-credential-report", debug=True)
        row = {"case": case, "operation": "GenerateCredentialReport", "observed_at": stamp(), **result}
        self.observations.append(self.normalize(row))
        self.write(False)
        print(case, json.dumps(result, sort_keys=True), flush=True)
        return result

    def write(self, cleanup_verified):
        fixture = {"schema_version": 1, "source": "Real AWS IAM API through AWS CLI; commercial partition",
                   "api_version": "2010-05-08", "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                   "aws_cli_version": subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip(),
                   "started_at": self.started, "finished_at": stamp(),
                   "probe": "scripts/aws/iam_credential_report_probe.py", "documentation": DOCUMENTATION,
                   "sanitization": "Only owned CSV rows retained; root values redacted to field shapes or sentinel values; unrelated user rows discarded. Account and owned names normalized. Passwords, access-key secrets, MFA seeds, private keys, raw CSV/base64/XML and debug logs never retained.",
                   "setup": self.normalize(self.setup), "observations": self.observations,
                   "limitations": self.limitations, "capture_complete": self.complete,
                   "cleanup_verified": cleanup_verified, "cleanup": self.normalize(self.cleanup)}
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(json.dumps(fixture, indent=2) + "\n")

    def finish(self):
        failures = []
        for item in reversed(self.owned):
            kind = item["kind"]
            if kind == "access-key":
                action, parameters = "delete-access-key", {"UserName": item["user"], "AccessKeyId": item["id"]}
            elif kind == "certificate":
                action, parameters = "delete-signing-certificate", {"UserName": item["user"], "CertificateId": item["id"]}
            elif kind == "login-profile":
                action, parameters = "delete-login-profile", {"UserName": item["id"]}
            elif kind == "mfa":
                try:
                    call("deactivate-mfa-device", {"UserName": item["user"], "SerialNumber": item["id"]})
                except RuntimeError:
                    # Continue deleting independent resources even if this
                    # device needs recovery from the ownership journal.
                    pass
                action, parameters = "delete-virtual-mfa-device", {"SerialNumber": item["id"]}
            else:
                action, parameters = "delete-user", {"UserName": item["id"]}
            try:
                result, _ = call(action, parameters)
            except RuntimeError:
                result = {"code": "CLITimeout"}
            self.cleanup.append({"operation": action, "input": parameters, "code": result["code"]})
            if result["code"] not in ("Success", "NoSuchEntity"):
                failures.append(item)
        for item in self.owned:
            if item["kind"] != "user":
                continue
            result, _ = call("get-user", {"UserName": item["id"]})
            self.cleanup.append({"operation": "get-user", "input": {"UserName": item["id"]}, "code": result["code"]})
            if result["code"] != "NoSuchEntity":
                failures.append(item)
        devices = {item["id"] for item in self.owned if item["kind"] == "mfa"}
        if devices:
            output = self.require("list-virtual-mfa-devices", {"AssignmentStatus": "Any", "MaxItems": 1000})
            absent = not output.get("IsTruncated", False) and not any(item["SerialNumber"] in devices for item in output["VirtualMFADevices"])
            self.cleanup.append({"operation": "list-virtual-mfa-devices", "owned_devices_absent": absent})
            if not absent:
                failures.extend(item for item in self.owned if item["kind"] == "mfa")
        if self.owned and self.first_content is not None:
            self.get("cached_report_after_owned_cleanup")
        self.write(not failures)
        if failures:
            raise RuntimeError("Cleanup incomplete; owned-resource journal: " + str(self.journal))
        self.journal.unlink(missing_ok=True)
        print("cleanup_verified", len(self.owned), "resources and credentials", flush=True)


def user(probe, suffix):
    name = probe.prefix + "-" + suffix
    output = probe.require("create-user", {"UserName": name, "Path": "/credential-report/"})["User"]
    probe.own("user", name)
    profile = {"user": name, "created_at": output["CreateDate"], "arn": output["Arn"],
               "password": "absent", "mfa_active": False, "keys": [], "certificates": []}
    probe.setup.append(profile)
    return profile


def password(probe, profile, reset_required=False):
    probe.require("create-login-profile", {"UserName": profile["user"], "Password": "aA1!" + secrets.token_urlsafe(100)[:124], "PasswordResetRequired": reset_required})
    probe.own("login-profile", profile["user"])
    output = probe.require("get-login-profile", {"UserName": profile["user"]})["LoginProfile"]
    profile.update({"password": "never_used", "password_reset_required": reset_required,
                    "password_created_at": output["CreateDate"]})


def access_key(probe, profile):
    output = probe.require("create-access-key", {"UserName": profile["user"]})["AccessKey"]
    probe.own("access-key", output["AccessKeyId"], user=profile["user"])
    label = "key_" + str(len(profile["keys"]) + 1)
    probe.identifiers[output["AccessKeyId"]] = profile["user"] + "-" + label
    profile["keys"].append({"label": label, "created_at": output["CreateDate"], "status": output["Status"]})
    return output


def key_pair(probe, profile, inactive_index):
    first = access_key(probe, profile)
    # AWS exposes whole-second creation dates. Future captures should avoid
    # a timestamp tie that could hide key slot ordering.
    time.sleep(1)
    keys = [first, access_key(probe, profile)]
    probe.require("update-access-key", {"UserName": profile["user"], "AccessKeyId": keys[inactive_index]["AccessKeyId"], "Status": "Inactive"})
    profile["keys"][inactive_index]["status"] = "Inactive"
    profile["keys"][inactive_index]["status_changed_at"] = stamp()
    profile["key_id_order_by_creation"] = "ascending" if keys[0]["AccessKeyId"] < keys[1]["AccessKeyId"] else "descending"
    return keys


def certificate(probe, profile):
    with tempfile.TemporaryDirectory(prefix="stackd-credential-cert-") as directory:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "private.pem", "-out", "certificate.pem", "-days", "2", "-subj", "/CN=stackd-credential.invalid"], cwd=directory, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output = probe.require("upload-signing-certificate", {"UserName": profile["user"], "CertificateBody": (Path(directory) / "certificate.pem").read_text()})["Certificate"]
    probe.own("certificate", output["CertificateId"], user=profile["user"])
    label = "certificate_" + str(len(profile["certificates"]) + 1)
    probe.identifiers[output["CertificateId"]] = profile["user"] + "-" + label
    profile["certificates"].append({"label": label, "uploaded_at": output["UploadDate"], "status": output["Status"]})
    return output


def totp(seed, step):
    digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def mfa(probe, profile):
    with tempfile.TemporaryDirectory(prefix="stackd-credential-mfa-") as directory:
        output = Path(directory) / "seed"
        process = run_cli("iam", "create-virtual-mfa-device", options=[*COMMON,
                         "--virtual-mfa-device-name", probe.prefix + "-mfa", "--outfile", str(output),
                         "--bootstrap-method", "Base32StringSeed"], timeout=60)
        if process.returncode:
            raise RuntimeError("CreateVirtualMFADevice failed; diagnostics discarded")
        serial = json.loads(process.stdout)["VirtualMFADevice"]["SerialNumber"]
        probe.own("mfa", serial, user=profile["user"])
        seed = base64.b32decode(output.read_bytes())
        step = int(time.time()) // 30
        probe.require("enable-mfa-device", {"UserName": profile["user"], "SerialNumber": serial,
                      "AuthenticationCode1": totp(seed, step - 1), "AuthenticationCode2": totp(seed, step)})
    profile["mfa_active"] = True


def configure(probe):
    # Creation and lexical order deliberately differ.
    user(probe, "z-bare")
    password(probe, user(probe, "d-password"))
    password(probe, user(probe, "c-reset-required"), reset_required=True)
    for suffix, index in (("b-keys-old-inactive", 0), ("a-keys-new-inactive", 1)):
        profile = user(probe, suffix)
        key_pair(probe, profile, index)
    used = user(probe, "e-key-used")
    key = access_key(probe, used)
    environment = dict(os.environ)
    for name in ("AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        environment.pop(name, None)
    environment.update({"AWS_ACCESS_KEY_ID": key["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": key["SecretAccessKey"],
                        "AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": os.devnull})
    used_successfully = False
    for attempt in range(8):
        response = subprocess.run(["aws", "sts", "get-caller-identity", "--region", "us-east-1", "--output", "json", "--no-cli-pager"], capture_output=True, text=True, timeout=30, env=environment)
        if response.returncode == 0:
            used_successfully = True
            break
        time.sleep(2)
    used["keys"][0]["successful_sts_get_caller_identity"] = used_successfully
    used["keys"][0]["last_used_api"] = probe.require("get-access-key-last-used", {"AccessKeyId": key["AccessKeyId"]})["AccessKeyLastUsed"]
    for suffix, index in (("f-certs-old-inactive", 0), ("g-certs-new-inactive", 1)):
        profile = user(probe, suffix)
        certificates = [certificate(probe, profile), certificate(probe, profile)]
        probe.require("update-signing-certificate", {"UserName": profile["user"], "CertificateId": certificates[index]["CertificateId"], "Status": "Inactive"})
        profile["certificates"][index]["status"] = "Inactive"
        profile["certificates"][index]["status_changed_at"] = stamp()
        profile["certificate_id_order_by_creation"] = "ascending" if certificates[0]["CertificateId"] < certificates[1]["CertificateId"] else "descending"
    deleted = user(probe, "h-password-deleted")
    password(probe, deleted)
    probe.require("delete-login-profile", {"UserName": deleted["user"]})
    deleted["password"] = "deleted_before_generation"
    mfa(probe, user(probe, "i-mfa"))
    probe.write(False)


def run(probe, inspect_only=False):
    identity = subprocess.run(["aws", "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], capture_output=True, text=True, check=True)
    probe.account = json.loads(identity.stdout)["Account"]
    existing = probe.get("existing_report")
    if inspect_only:
        probe.limitations.append("Read-only inspection only; report generation and owned user scenarios have not run.")
        probe.complete = True
        return
    cached = False
    if existing["code"] == "Success":
        generated = datetime.datetime.fromisoformat(existing["output"]["GeneratedTime"].replace("Z", "+00:00"))
        cached = datetime.datetime.now(datetime.timezone.utc) - generated < datetime.timedelta(hours=4)
    if cached:
        user(probe, "cache-absent")
        probe.limitations.append("An existing report is less than four hours old. Varied user profiles were skipped because AWS would reuse it; a single owned new user tests cache immutability without a four-hour wait.")
    else:
        configure(probe)
    probe.generate("generate_initial")
    probe.get("get_immediately_after_generate")
    for attempt in range(30):
        state = probe.generate("generate_poll_" + str(attempt + 1))
        if state.get("output", {}).get("State") == "COMPLETE":
            break
        time.sleep(2)
    else:
        probe.limitations.append("Generation did not complete within the bounded one-minute polling window.")
        return
    final = probe.get("completed_report")
    if final["code"] != "Success":
        return
    probe.generate("generate_cached_repeat")
    probe.get("cached_report_repeat")
    if not cached:
        # Mutation after generation must not change the cached artifact.
        user(probe, "post-generation")
        probe.generate("generate_after_new_user")
        probe.get("cached_report_after_new_user")
    probe.limitations.append("Four-hour cache expiry and expired-report errors were not reached by waiting; documented separately in primary AWS references.")
    completed = next(row for row in probe.observations if row["case"] == "completed_report")
    if "additional_credentials_info" not in completed["header"]:
        probe.limitations.append("The live report header omits additional_credentials_info, although the current primary User Guide lists that column. No claim is made about accounts with more than two keys or certificates per user.")
    probe.limitations.extend([
        "A small number of owned credential pairs does not establish all sorting or tie-breaking rules; creation times, status and ID-order observations are recorded separately.",
        "Owned profiles share one IAM path; their order alone does not establish ordering across paths. Unrelated identities and contents were discarded.",
        "Recent successful use need not immediately appear in GetAccessKeyLastUsed or a generated report. The captured values establish observations at those timestamps, not that the call never updates usage.",
        "Password policy, root credentials and root settings were not modified. Password rotation with an account maximum age was not exercised.",
    ])
    if not any(row.get("output", {}).get("State") == "INPROGRESS" for row in probe.observations):
        probe.limitations.append("INPROGRESS is a documented Generate state but was not observed in this run. It is distinct from Get returning the ReportInProgress error.")
    probe.complete = True


if __name__ == "__main__":
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--account", required=True)
    arguments = parser.parse_args()
    require_account(arguments.account)
    probe = Probe()
    try:
        run(probe, arguments.inspect_only)
    finally:
        probe.finish()
