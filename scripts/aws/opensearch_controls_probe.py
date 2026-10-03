#!/usr/bin/env python3
"""Capture free OpenSearch/ES controls and an owned IAM rename matrix.

No domain creation, standing-resource mutation, Organizations call, or trail
configuration is permitted. Invalid version/name cases use read-only methods.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudtrail_events import CollectionError, collect_history
from cloudtrail_service_probe import document

REGION = "us-east-1"
CONFIG = Config(region_name=REGION, retries={"total_max_attempts": 1},
                connect_timeout=10, read_timeout=30, ignore_configured_endpoint_urls=True)
ROOT = Path(__file__).resolve().parents[2]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def revision(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


class Probe:
    def __init__(self, args):
        self.args = args
        self.session = boto3.Session(region_name=REGION)
        self.clients = {name: self.session.client(name, config=CONFIG)
                        for name in ("sts", "iam", "opensearch", "es", "cloudtrail")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != self.args.account:
            raise RuntimeError("Native probe restricted to the authorized account")
        if args.audit_only or args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["account"] != self.args.account or self.data["region"] != REGION:
                raise RuntimeError("Capture account/region differs from authorized target")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite existing native evidence")
            prefix = "stackd-os-" + uuid.uuid4().hex[:16]
            self.data = {
                "account": self.args.account, "region": REGION, "prefix": prefix,
                "captured_at": now(), "identity": document(identity),
                "scope": "Free read-only controls and deletion of a confirmed nonexistent random domain; one owned short-lived IAM role only",
                "exclusions": ["No CreateDomain or CreateElasticsearchDomain call",
                               "No native domain, data-plane or resource-policy calibration",
                               "No standing-resource or Organizations mutation",
                               "Missing bounded CloudTrail observations do not establish event absence"],
                "redaction": "cloudtrail_service_probe.document: credential secrets removed, access-key presence and IP family retained; owner sanitization, not AWS masking",
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                        "credential_method": self.session.get_credentials().method,
                        "retry_total_max_attempts": 1},
                "sources": {
                    "repository_revision": revision(ROOT),
                    "aws_sdk_go_v2_revision": revision(ROOT / "clones/aws-sdk-go-v2"),
                    "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "documentation": [
                        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudtrailauditing.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_ListDomainNames.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_ListVersions.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DescribeDomain.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DescribeDomainConfig.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DeleteDomain.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_ListInstanceTypeDetails.html",
                        "https://docs.aws.amazon.com/opensearch-service/latest/APIReference/Welcome.html"]},
                "calls": [], "owned": {}, "cleanup": {}, "iam_matrix": [],
                "audit": {}, "commands": [],
            }
        self.data["commands"].append({"at": now(), "cwd": str(Path.cwd()),
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "command": "PYTHONPATH=scripts/aws python3 -B -P " + shlex.join(sys.argv)})
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(document(self.data), indent=2) + "\n")

    def call(self, label, client, method, parameters=None, caller="owner"):
        parameters = parameters or {}
        operation = client.meta.method_to_api_mapping[method]
        row = {"label": label, "service": client.meta.service_model.service_name,
               "api_version": client.meta.service_model.api_version,
               "operation": operation, "method": method, "input": document(parameters),
               "caller": caller, "endpoint": client.meta.endpoint_url, "started_at": now()}
        try:
            result = getattr(client, method)(**parameters)
            metadata = result.get("ResponseMetadata", {})
            row.update(code="Success", output=document({k: v for k, v in result.items()
                                                       if k != "ResponseMetadata"}))
        except ClientError as error:
            result = error.response
            metadata = result.get("ResponseMetadata", {})
            row.update(code=result["Error"]["Code"], error=document(result["Error"]),
                       exception_class=type(error).__name__,
                       modeled_error=type(error) is not ClientError,
                       output=document({k: v for k, v in result.items()
                                        if k not in ("Error", "ResponseMetadata")}))
        except Exception as error:
            row.update(code="ClientFailure", exception_class=type(error).__name__, message=str(error), finished_at=now())
            self.data["calls"].append(row)
            self.save()
            raise
        row.update(request_id=metadata.get("RequestId"), http_status=metadata.get("HTTPStatusCode"),
                   response_metadata=document(metadata), finished_at=now())
        self.data["calls"].append(row)
        self.save()
        print(label + ": " + row["code"], flush=True)
        return row, result

    def controls(self):
        name = self.data["prefix"]
        for service, describe, config, delete, versions in (
                ("opensearch", "describe_domain", "describe_domain_config", "delete_domain", "list_versions"),
                ("es", "describe_elasticsearch_domain", "describe_elasticsearch_domain_config",
                 "delete_elasticsearch_domain", "list_elasticsearch_versions")):
            client = self.clients[service]
            row, result = self.call(service + "-list-domains", client, "list_domain_names")
            if row["code"] != "Success" or any(domain["DomainName"] == name for domain in result.get("DomainNames", [])):
                raise RuntimeError("Cannot prove random domain is absent from native inventory")
            self.call(service + "-versions", client, versions, {"MaxResults": 100})
            absent, _ = self.call(service + "-missing-domain", client, describe, {"DomainName": name})
            self.call(service + "-missing-config", client, config, {"DomainName": name})
            # Never issue Delete unless the exact fresh name was confirmed absent.
            if absent["code"] != "ResourceNotFoundException":
                raise RuntimeError("Refusing Delete: nonexistent-domain precondition unproven")
            self.call(service + "-delete-missing-domain", client, delete, {"DomainName": name})
            self.call(service + "-invalid-name", client, describe, {"DomainName": "INVALID_NAME"})
        self.call("opensearch-invalid-engine-version", self.clients["opensearch"],
                  "list_instance_type_details", {"EngineVersion": "OpenSearch_99.99", "MaxResults": 1})
        self.call("es-invalid-engine-version", self.clients["es"],
                  "list_elasticsearch_instance_types", {"ElasticsearchVersion": "99.99", "MaxResults": 1})

    def matrix(self):
        iam, sts = self.clients["iam"], self.clients["sts"]
        role = self.data["prefix"] + "-rename"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"AWS": self.data["identity"]["Arn"]}}]}
        self.data["owned"] = {"role_name": role, "role_arn": f"arn:aws:iam::{self.args.account}:role/{role}",
                              "policy_name": "RenameProbe", "create_attempted": True}
        self.save()
        row, result = self.call("iam-create-owned-role", iam, "create_role", {
            "RoleName": role, "AssumeRolePolicyDocument": json.dumps(trust),
            "Description": "Owned bounded free OpenSearch rename calibration",
            "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]})
        if row["code"] != "Success":
            self.data["iam_matrix_unavailable"] = {"stage": "CreateRole", "code": row["code"]}
            self.save()
            return
        self.data["owned"]["role_id"] = result["Role"]["RoleId"]
        self.save()
        assumed = None
        for attempt in range(1, 7):
            row, result = self.call(f"iam-assume-role-{attempt}", sts, "assume_role", {
                "RoleArn": self.data["owned"]["role_arn"], "RoleSessionName": "rename-calibration", "DurationSeconds": 900})
            if row["code"] == "Success":
                assumed = result["Credentials"]
                break
            if row["code"] != "AccessDenied":
                break
            time.sleep(5)
        if assumed is None:
            self.data["iam_matrix_unavailable"] = {"stage": "AssumeRole", "code": row["code"]}
            self.save()
            return
        reader = boto3.Session(aws_access_key_id=assumed["AccessKeyId"],
                               aws_secret_access_key=assumed["SecretAccessKey"],
                               aws_session_token=assumed["SessionToken"], region_name=REGION)
        clients = {service: reader.client(service, config=CONFIG) for service in ("opensearch", "es")}
        old, new = "es:DescribeElasticsearchDomain", "es:DescribeDomain"
        for label, allows, denies in (
                ("both-allow", [old, new], []), ("old-allow", [old], []), ("new-allow", [new], []),
                ("old-allow-new-deny", [old], [new]), ("new-allow-old-deny", [new], [old]),
                ("both-allow-old-deny", [old, new], [old]), ("both-allow-new-deny", [old, new], [new])):
            statements = [{"Effect": "Allow", "Action": allows, "Resource": "*"}]
            if denies:
                statements.append({"Effect": "Deny", "Action": denies, "Resource": "*"})
            policy = {"Version": "2012-10-17", "Statement": statements}
            row, _ = self.call("iam-policy-" + label, iam, "put_role_policy", {
                "RoleName": role, "PolicyName": "RenameProbe", "PolicyDocument": json.dumps(policy)})
            if row["code"] != "Success":
                self.data["iam_matrix_unavailable"] = {"stage": "PutRolePolicy", "code": row["code"]}
                self.save()
                return
            entry = {"label": label, "policy": policy, "policy_request_id": row["request_id"],
                     "observation_boundary": "Two fixed 15-second propagation intervals; no assertion that IAM propagation completed", "rounds": []}
            self.data["iam_matrix"].append(entry)
            for round_number in (1, 2):
                time.sleep(15)
                outcomes = {"round": round_number, "seconds_after_policy_ack_at_least": round_number * 15, "calls": []}
                for service, method in (("opensearch", "describe_domain"), ("es", "describe_elasticsearch_domain")):
                    row, _ = self.call(f"iam-{label}-{service}-round-{round_number}", clients[service], method,
                                      {"DomainName": self.data["prefix"]}, caller="owned-assumed-role")
                    outcomes["calls"].append({"label": row["label"], "code": row["code"],
                                              "request_id": row["request_id"], "http_status": row["http_status"]})
                entry["rounds"].append(outcomes)
                self.save()

    def cleanup(self):
        owned = self.data["owned"]
        if not owned:
            return
        iam = self.clients["iam"]
        row, result = self.call("cleanup-inspect-role", iam, "get_role", {"RoleName": owned["role_name"]})
        if row["code"] == "NoSuchEntity":
            self.data["cleanup"].update(role_absent=True, absence_request_id=row["request_id"])
            self.save()
            return
        if row["code"] != "Success":
            raise RuntimeError("Cannot inspect owned role for cleanup")
        role = result["Role"]
        tags = {tag["Key"]: tag["Value"] for tag in role.get("Tags", [])}
        if (role["Arn"] != owned["role_arn"] or tags.get("stackd-probe") != self.data["prefix"] or
                (owned.get("role_id") and role["RoleId"] != owned["role_id"])):
            raise RuntimeError("Refusing cleanup of a role without exact ownership")
        deletion, _ = self.call("cleanup-delete-inline-policy", iam, "delete_role_policy", {
            "RoleName": owned["role_name"], "PolicyName": owned["policy_name"]})
        policy_absent, _ = self.call("cleanup-inline-policy-absence", iam, "get_role_policy", {
            "RoleName": owned["role_name"], "PolicyName": owned["policy_name"]})
        if deletion["code"] not in ("Success", "NoSuchEntity") or policy_absent["code"] != "NoSuchEntity":
            raise RuntimeError("Owned inline policy cleanup unproven")
        deletion, _ = self.call("cleanup-delete-role", iam, "delete_role", {"RoleName": owned["role_name"]})
        absence, _ = self.call("cleanup-role-absence", iam, "get_role", {"RoleName": owned["role_name"]})
        self.data["cleanup"] = {"role_absent": absence["code"] == "NoSuchEntity",
                                "inline_policy_absent": True,
                                "policy_absence_request_id": policy_absent["request_id"],
                                "absence_request_id": absence["request_id"],
                                "role_delete_code": deletion["code"], "finished_at": now()}
        self.save()
        if deletion["code"] not in ("Success", "NoSuchEntity") or not self.data["cleanup"]["role_absent"]:
            raise RuntimeError("Owned role cleanup unproven")

    def audit(self):
        requests = {row["request_id"]: row["label"] for row in self.data["calls"] if row.get("request_id")}
        history = self.clients["cloudtrail"]
        start = dt.datetime.fromisoformat(self.data["captured_at"]) - dt.timedelta(minutes=1)
        try:
            self.data["audit"] = collect_history(lambda params: history.lookup_events(**params), requests,
                start_time=start, event_sources=("es.amazonaws.com", "iam.amazonaws.com", "sts.amazonaws.com"),
                max_pages=10, rounds=self.args.audit_rounds, wait_seconds=self.args.audit_wait,
                previous=self.data["audit"] or None)
        except CollectionError as error:
            self.data["audit"] = error.result
            raise
        finally:
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".stackd/probes/opensearch/controls.json")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit-only", action="store_true")
    mode.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--audit-rounds", type=int, default=10)
    parser.add_argument("--audit-wait", type=float, default=30)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if not 1 <= args.audit_rounds <= 20 or not 0 <= args.audit_wait <= 60:
        parser.error("Audit bounds require 1..20 rounds and 0..60 second intervals")
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"Signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    probe = Probe(args)
    if args.cleanup_only:
        probe.cleanup()
    elif args.audit_only:
        probe.audit()
    else:
        try:
            probe.controls()
            probe.matrix()
        finally:
            probe.cleanup()
        probe.audit()
    print(json.dumps({"fixture": str(args.output), "calls": len(probe.data["calls"]),
                      "iam_matrix_cases": len(probe.data["iam_matrix"]), "cleanup": probe.data["cleanup"],
                      "audit_events": len(probe.data["audit"].get("events", [])),
                      "audit_missing_calls": probe.data["audit"].get("missing_calls", [])}))


if __name__ == "__main__":
    main()
