#!/usr/bin/env python3
"""Native AppRegistry eligibility and boundaries; no account setting writes.

Requires ambient credentials for the pinned authorized account. Endpoint overrides
are disabled. Responses/request IDs are retained, never credential material.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import sys
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


ROOT = Path(__file__).resolve().parents[2] / ".stackd/probes/appregistry"
SOURCES = [
    "https://docs.aws.amazon.com/servicecatalog/latest/arguide/app-registry-availability-change.html",
    "https://docs.aws.amazon.com/servicecatalog/latest/APIReference/API_app-registry_CreateApplication.html",
    "https://docs.aws.amazon.com/servicecatalog/latest/APIReference/API_app-registry_DeleteApplication.html",
    "https://docs.aws.amazon.com/servicecatalog/latest/APIReference/API_app-registry_AssociateResource.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_GroupResources.html",
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def redact(value):
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()
                if key.lower() not in ("accesskeyid", "secretaccesskey", "sessiontoken",
                                       "authorization", "credentials")}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class Capture:
    def __init__(self, args):
        self.args = args
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        self.session = boto3.Session(region_name=args.region)
        self.config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                             retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=40)
        self.clients = {service: self.session.client(service, config=self.config) for service in
                        ("sts", "servicecatalog-appregistry", "resource-groups", "cloudtrail")}
        identity = self.clients["sts"].get_caller_identity()
        if identity["Account"] != args.account:
            raise RuntimeError("Only the authorized native account may be probed")
        self.prefix = "stackd-ar-" + uuid.uuid4().hex[:12]
        self.fixture = {
            "captured_at": now(), "region": args.region, "identity": identity,
            "sources": SOURCES, "sdk": {"boto3": boto3.__version__},
            "scope": "Exact-owned AppRegistry application/attribute-group eligibility. No account-wide GLE or AppRegistry configuration writes; no downstream owners provisioned without admission.",
            "owned": {"prefix": self.prefix, "applications": [], "attribute_groups": [],
                      "resources": [], "groups": []},
            "observations": [], "cleanup": [], "effects": [],
            "boundary": "API admission is not proof of eventual tagging or membership. Missing effects/events within bounded observation do not establish permanent absence.",
        }
        self.cleanup_phase = False
        self.applications = []
        self.attributes = []

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(redact(self.fixture), indent=2, default=str) + "\n")

    def call(self, service, operation, case, **request):
        row = {"case": case, "service": service, "operation": operation,
               "input": request, "at": now()}
        try:
            response = getattr(self.clients[service], operation)(**request)
            row["code"] = "Success"
        except ClientError as error:
            response = error.response
            row["code"] = response.get("Error", {}).get("Code")
        metadata = response.pop("ResponseMetadata", {})
        row.update(http_status=metadata.get("HTTPStatusCode"),
                   request_id=metadata.get("RequestId"), output=response)
        self.fixture["cleanup" if self.cleanup_phase else "observations"].append(row)
        self.save()
        print(json.dumps({key: row[key] for key in ("case", "code", "request_id")}), flush=True)
        return row

    def ar(self, operation, case, **request):
        return self.call("servicecatalog-appregistry", operation, case, **request)

    def rg(self, operation, case, **request):
        return self.call("resource-groups", operation, case, **request)

    def create_application(self, suffix):
        row = self.ar("create_application", "create-application-" + suffix,
                      name=self.prefix + "-" + suffix, description="Exact-owned native probe",
                      tags={"stackd-appregistry-probe": self.prefix}, clientToken=uuid.uuid4().hex)
        if row["code"] == "Success":
            app = row["output"]["application"]
            self.applications.append(app)
            self.fixture["owned"]["applications"].append(app)
            self.save()
            return app
        return None

    def eligibility(self):
        self.rg("get_account_settings", "account-settings-before")
        self.ar("get_configuration", "appregistry-settings-before")
        app = self.create_application("eligibility")
        attr = self.ar("create_attribute_group", "create-attribute-eligibility",
                       name=self.prefix + "-attributes", attributes='{"probe":true}',
                       tags={"stackd-appregistry-probe": self.prefix}, clientToken=uuid.uuid4().hex)
        if attr["code"] == "Success":
            self.attributes.append(attr["output"]["attributeGroup"])
            self.fixture["owned"]["attribute_groups"].extend(self.attributes)
        self.fixture["eligibility"] = {"application_created": app is not None,
                                       "attribute_created": attr["code"] == "Success"}
        self.save()
        return app

    def boundaries(self):
        original = json.loads((ROOT / "native-eligibility.json").read_text())
        if (original["identity"]["Account"] != self.fixture["identity"]["Account"]
                or original["region"] != self.args.region):
            raise RuntimeError("Eligibility fixture has a different native scope")
        self.prefix = original["owned"]["prefix"]
        self.fixture["owned"]["prefix"] = self.prefix
        self.fixture["input_fixture"] = "native-eligibility.json"
        self.fixture["scope"] = "Exact names rejected by the eligibility probe, plus malformed identifiers. No owner resources or settings are mutated."
        app = self.prefix + "-eligibility"
        attr = self.prefix + "-attributes"
        self.rg("get_account_settings", "account-settings-before")
        self.ar("get_configuration", "appregistry-settings-before")
        for kind, key, value in (("application", "application", app),
                                 ("attribute_group", "attributeGroup", attr)):
            self.ar("get_" + kind, kind + "-missing", **{key: value})
            self.ar("get_" + kind, kind + "-invalid-identifier", **{key: value + " "})
            self.ar("update_" + kind, kind + "-update-empty", **{key: value})
            self.ar("update_" + kind, kind + "-update-description",
                    **{key: value, "description": "Exact-owned absent boundary"})
            self.ar("update_" + kind, kind + "-update-name",
                    **{key: value, "name": value + "-renamed"})
            self.ar("update_" + kind, kind + "-update-long-description",
                    **{key: value, "description": "x" * 1025})
            self.ar("delete_" + kind, kind + "-delete-missing", **{key: value})
        for label, attributes in (("invalid-json", "{"), ("array", "[]"),
                                  ("scalar", "1"), ("empty-object", "{}"),
                                  ("empty", ""), ("unicode", '{"value":"\\u2603"}')):
            self.ar("update_attribute_group", "attribute-update-" + label,
                    attributeGroup=attr, attributes=attributes)
        for operation in ("associate_attribute_group", "disassociate_attribute_group"):
            self.ar(operation, operation + "-missing", application=app, attributeGroup=attr)
        for operation in ("list_associated_resources", "list_associated_attribute_groups",
                          "list_attribute_groups_for_application"):
            self.ar(operation, operation + "-missing", application=app)
        account = self.fixture["identity"]["Account"]
        stack = f"arn:aws:cloudformation:{self.args.region}:{account}:stack/{self.prefix}/00000000-0000-0000-0000-000000000000"
        for resource_type, resource in (("CFN_STACK", stack), ("RESOURCE_TAG_VALUE", self.prefix)):
            self.ar("associate_resource", "associate-missing-" + resource_type,
                    application=app, resourceType=resource_type, resource=resource,
                    options=["APPLY_APPLICATION_TAG"])
            self.ar("get_associated_resource", "association-get-missing-" + resource_type,
                    application=app, resourceType=resource_type, resource=resource)
            self.ar("disassociate_resource", "disassociate-missing-" + resource_type,
                    application=app, resourceType=resource_type, resource=resource)
        group = "AWS_AppRegistry_Application-" + app
        for operation in ("get_group", "get_group_configuration", "list_group_resources",
                          "list_grouping_statuses"):
            self.rg(operation, operation + "-uncreated-application", Group=group)
        for operation in ("group_resources", "ungroup_resources"):
            self.rg(operation, operation + "-uncreated-application",
                    Group=group, ResourceArns=[f"arn:aws:s3:::{self.prefix}"])
        self.fixture["positive_effects_unavailable"] = [
            "CreateApplication and CreateAttributeGroup eligibility refusals prevent managed group, owner tag, association, deletion/recreation and delegated IAM effects.",
            "No S3/SQS/SSM/CloudFormation owners are provisioned: manually applying an invented application tag would not prove AppRegistry integration.",
            "Missing targets reveal only the observed validation/lookup order, not successful resource behavior.",
        ]
        self.cleanup_phase = True
        for kind, key, value in (("application", "application", app),
                                 ("attribute_group", "attributeGroup", attr)):
            row = self.ar("get_" + kind, kind + "-exact-attempted-name-absent", **{key: value})
            if row["code"] != "ResourceNotFoundException":
                self.fixture.setdefault("absence_unverified", []).append(kind)
        self.save()

    def audit(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from cloudtrail_events import CollectionError, collect_history

        fixture_names = ("native-eligibility.json", "native-boundaries.json")
        captures = [json.loads((ROOT / name).read_text()) for name in fixture_names]
        if any(capture["identity"]["Account"] != self.fixture["identity"]["Account"]
               or capture["region"] != self.args.region for capture in captures):
            raise RuntimeError("Audit fixture has a different native scope")
        requests = {
            row["request_id"]: filename + ":" + row["case"]
            for filename, capture in zip(fixture_names, captures)
            for row in capture["observations"] + capture["cleanup"]
            if row.get("request_id")
        }
        start = min(datetime.datetime.fromisoformat(capture["captured_at"]) for capture in captures)
        previous = None
        end = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if self.args.output.exists():
            prior = json.loads(self.args.output.read_text())
            if (prior["identity"]["Account"] != self.fixture["identity"]["Account"]
                    or prior["region"] != self.args.region
                    or prior["input_fixtures"] != list(fixture_names)):
                raise RuntimeError("Prior audit has a different native scope")
            previous = prior["collection"]
            end = previous["bounds"]["end_time"]
        failure = None
        try:
            result = collect_history(
                lambda request: self.clients["cloudtrail"].lookup_events(**request), requests,
                start_time=start, end_time=end,
                event_sources=("servicecatalog-appregistry.amazonaws.com", "servicecatalog.amazonaws.com",
                               "resource-groups.amazonaws.com"),
                max_pages=20, rounds=self.args.audit_rounds,
                wait_seconds=self.args.audit_wait, previous=previous)
        except CollectionError as error:
            result = error.result
            failure = error
        self.fixture = {
            "captured_at": now(), "region": self.args.region, "identity": self.fixture["identity"],
            "scope": "Read-only CloudTrail lookup; retain exact request-ID matches only, discard unrelated events.",
            "input_fixtures": list(fixture_names), "collection": result,
            "redaction": "Credential fields removed recursively from events and lookup metadata.",
            "boundary": "Missing or late events were not observed within bounded collection; not evidence AWS omits them.",
        }
        self.save()
        print(json.dumps({"events": len(result["events"]),
                          "missing_request_ids": len(result["missing_request_ids"]),
                          "pages": len(result["pages"]), "partial": result["partial"]}))
        if failure:
            raise failure

    def cleanup(self):
        self.cleanup_phase = True
        failures = []
        for attr in reversed(self.attributes):
            self.ar("delete_attribute_group", "cleanup-attribute", attributeGroup=attr["id"])
            row = self.ar("get_attribute_group", "attribute-absent", attributeGroup=attr["id"])
            if row["code"] != "ResourceNotFoundException":
                failures.append("attribute:" + attr["id"])
        for app in reversed(self.applications):
            self.ar("delete_application", "cleanup-application", application=app["id"])
            row = self.ar("get_application", "application-absent", application=app["id"])
            if row["code"] != "ResourceNotFoundException":
                failures.append("application:" + app["id"])
        self.rg("get_account_settings", "account-settings-after")
        self.ar("get_configuration", "appregistry-settings-after")
        self.fixture["cleanup_verified"] = not failures and not self.fixture.get("absence_unverified")
        self.fixture["cleanup_failures"] = failures
        self.fixture["finished_at"] = now()
        self.save()
        if not self.fixture["cleanup_verified"]:
            raise RuntimeError("Exact-owned cleanup not verified; see fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--boundaries", action="store_true",
                      help="Use exact attempted names in native-eligibility.json; no provisioning")
    mode.add_argument("--audit", action="store_true", help="Read-only exact-request CloudTrail lookup")
    parser.add_argument("--audit-rounds", type=int, default=3)
    parser.add_argument("--audit-wait", type=float, default=60)
    args = parser.parse_args()
    if args.output is None:
        suffix = "audit" if args.audit else "boundaries" if args.boundaries else "eligibility"
        args.output = ROOT / ("native-" + suffix + ".json")
    capture = Capture(args)
    if args.audit:
        capture.audit()
        return
    try:
        if args.boundaries:
            capture.boundaries()
        else:
            capture.eligibility()
    finally:
        capture.cleanup()


if __name__ == "__main__":
    main()
