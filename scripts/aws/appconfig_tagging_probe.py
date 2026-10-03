#!/usr/bin/env python3
"""Capture exact-owned AppConfig tagging controls; resume with --cleanup-only.

No configuration versions, deployments, retrieval, compute, or IAM writes.
The output is also the durable ownership ledger; never overwrite a prior run.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import call as cli_call

REGION = "us-east-1"
OWNER_KEY = "stackd-appconfig-tagging-probe"
KINDS = ("application", "environment", "configurationprofile", "deploymentstrategy")
METHODS = {"application": "application", "environment": "environment",
           "configurationprofile": "configuration_profile", "deploymentstrategy": "deployment_strategy"}
SOURCES = [
    "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ResourceGroupsTaggingAPITagUntagSupportedResources.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_TagResources.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_UntagResources.html",
    "https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_TagResource.html",
    "https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_ListTagsForResource.html",
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html",
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Capture:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        env = dict(os.environ, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true",
                   AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1")
        identity = cli_call("sts", "get-caller-identity", env=env)
        config = Config(ignore_configured_endpoint_urls=True,
                        retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
        session = boto3.Session(region_name=REGION)
        sdk_identity = session.client("sts", config=config).get_caller_identity()
        if identity["Account"] != self.account or sdk_identity["Arn"] != identity["Arn"]:
            raise RuntimeError("Refusing unexpected native identity")
        self.clients = {service: session.client(service, config=config) for service in
                        ("appconfig", "resourcegroupstaggingapi")}
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if self.data["identity"]["Account"] != self.account or self.data["region"] != REGION:
                raise RuntimeError("Cleanup ledger scope mismatch")
            self.data.setdefault("cleanup_resumes", []).append({"at": now(), "identity": identity})
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite evidence; use --cleanup-only")
            models = {}
            for service in self.clients:
                model = session._session.get_component("data_loader").load_service_model(service, "service-2")
                models[service] = {"api_version": model["metadata"]["apiVersion"],
                                   "sha256": hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()}
            self.data = {
                "captured_at": now(), "identity": identity, "sdk_identity": sdk_identity,
                "region": REGION, "source_urls": SOURCES,
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__, "models": models},
                "scope": "One free exact-owned application, environment, hosted configuration profile without versions, and custom zero-duration strategy. No deployments, configuration retrieval, extension invocation, compute, IAM, or standing resource mutation.",
                "limitations": ["Only the four recorded types and filter spellings are measured; no general AppConfig or IAM parity claim.",
                                "Bounded discovery absence is not evidence of permanent ineligibility.",
                                "Previously-tagged empty membership is measured with ResourceARNList, not an account-wide unfiltered scan."],
                "owned": {"name": "stackd-ac-tags-" + uuid.uuid4().hex[:16], "resources": {}},
                "observations": [], "cleanup": [], "complete": False, "cleanup_verified": False,
            }
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.args.output.with_suffix(".json.tmp")
        with temporary.open("w") as stream:
            json.dump(self.data, stream, indent=2, default=str)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.args.output)
        directory = os.open(self.args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def call(self, service, method, case, **request):
        client = self.clients[service]
        row = {"case": case, "at": now(), "service": service,
               "operation": client.meta.method_to_api_mapping[method], "input": request}
        try:
            row.update(code="Success", output=getattr(client, method)(**request))
        except ClientError as error:
            row.update(code=error.response["Error"]["Code"], output=error.response)
        self.data["cleanup" if self.cleanup_phase else "observations"].append(row)
        self.save()
        print(json.dumps({"case": case, "code": row["code"]}), flush=True)
        return row

    @staticmethod
    def success(row):
        if row["code"] != "Success":
            raise RuntimeError(row["case"] + ": " + row["code"])
        return row["output"]

    def arn(self, kind, resource_id):
        base = f"arn:aws:appconfig:{REGION}:{self.account}:"
        if kind in ("environment", "configurationprofile"):
            base += "application/" + self.data["owned"]["resources"]["application"]["id"] + "/"
        return base + kind + "/" + resource_id

    def remember(self, kind, resource_id):
        entry = self.data["owned"]["resources"][kind]
        entry.update(id=resource_id, arn=self.arn(kind, resource_id))
        self.save()

    def create(self, kind, **request):
        request.update(Name=self.data["owned"]["name"], Tags={OWNER_KEY: self.data["owned"]["name"]})
        self.data["owned"]["resources"][kind] = {"create_input": request, "intent_at": now()}
        self.save()
        row = self.call("appconfig", "create_" + METHODS[kind], "create-" + kind, **request)
        output = self.success(row)
        self.remember(kind, output["Id"])
        return output["Id"]

    def discover(self, case, filters):
        request = {"TagFilters": [{"Key": OWNER_KEY, "Values": [self.data["owned"]["name"]]}],
                   "ResourceTypeFilters": filters, "ResourcesPerPage": 100}
        found = []
        while True:
            output = self.success(self.call("resourcegroupstaggingapi", "get_resources", case, **request))
            found.extend(item["ResourceARN"] for item in output["ResourceTagMappingList"])
            if not output.get("PaginationToken"):
                return sorted(found)
            request["PaginationToken"] = output["PaginationToken"]

    def native_tags(self, case, expected):
        for kind, entry in self.data["owned"]["resources"].items():
            output = self.success(self.call("appconfig", "list_tags_for_resource", case + "-" + kind,
                                            ResourceArn=entry["arn"]))
            if output["Tags"] != expected:
                raise RuntimeError("Native tags differ from requested state for " + kind)

    def capture(self):
        app = self.create("application")
        self.create("environment", ApplicationId=app)
        self.create("configurationprofile", ApplicationId=app, LocationUri="hosted", Type="AWS.Freeform")
        self.create("deploymentstrategy", DeploymentDurationInMinutes=0, GrowthFactor=100,
                    GrowthType="LINEAR", FinalBakeTimeInMinutes=0, ReplicateTo="NONE")
        arns = sorted(entry["arn"] for entry in self.data["owned"]["resources"].values())
        initial = {OWNER_KEY: self.data["owned"]["name"]}
        self.native_tags("initial-tags", initial)
        deadline = time.monotonic() + 180
        attempt = 0
        while True:
            found = self.discover("service-discovery-" + str(attempt), ["appconfig"])
            if found == arns or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(10)
        self.data["service_discovery_complete"] = found == arns
        self.data["resource_type_filters"] = {}
        for value in ["appconfig"] + ["appconfig:" + kind for kind in KINDS]:
            matched = self.discover("type-filter-" + value, [value])
            self.data["resource_type_filters"][value] = matched
            self.save()
            print(json.dumps({"resource_type_filter": value, "matched": matched}), flush=True)
        output = self.success(self.call("resourcegroupstaggingapi", "tag_resources", "tag-owned-resources",
                                        ResourceARNList=arns, Tags={"roundtrip": "native-reflection"}))
        if output["FailedResourcesMap"]:
            raise RuntimeError("TagResources rejected owned resources")
        self.native_tags("after-tag-resources", dict(initial, roundtrip="native-reflection"))
        self.success(self.call("resourcegroupstaggingapi", "get_resources", "explicit-after-tagging", ResourceARNList=arns))
        output = self.success(self.call("resourcegroupstaggingapi", "untag_resources", "untag-roundtrip",
                                        ResourceARNList=arns, TagKeys=["roundtrip"]))
        if output["FailedResourcesMap"]:
            raise RuntimeError("UntagResources rejected owned resources")
        self.native_tags("after-untag-resources", initial)
        output = self.success(self.call("resourcegroupstaggingapi", "untag_resources", "terminal-untag",
                                        ResourceARNList=arns, TagKeys=[OWNER_KEY]))
        if output["FailedResourcesMap"]:
            raise RuntimeError("Terminal UntagResources rejected owned resources")
        self.native_tags("after-terminal-untag", {})
        output = self.success(self.call("resourcegroupstaggingapi", "get_resources", "explicit-after-terminal-untag",
                                        ResourceARNList=arns))
        self.data["terminal_untag_mappings"] = output["ResourceTagMappingList"]
        self.data["complete"] = True
        self.save()

    def recover(self, kind, entry):
        if "id" in entry:
            return
        method = "create_" + METHODS[kind]
        operation = self.clients["appconfig"].meta.method_to_api_mapping[method]
        for row in self.data["observations"]:
            if row["operation"] == operation and row["code"] == "Success":
                self.remember(kind, row["output"]["Id"])
                return
        request = {}
        if "ApplicationId" in entry["create_input"]:
            request["ApplicationId"] = entry["create_input"]["ApplicationId"]
        matches = []
        for page in range(100):
            output = self.success(self.call("appconfig", "list_" + METHODS[kind] + "s",
                                            "recover-" + kind + "-" + str(page), **request))
            matches.extend(item for item in output["Items"] if item["Name"] == self.data["owned"]["name"])
            if not output.get("NextToken"):
                break
            request["NextToken"] = output["NextToken"]
        else:
            raise RuntimeError("Recovery pagination bound reached")
        if len(matches) > 1:
            raise RuntimeError("Ambiguous exact-name recovery; refusing mutation")
        if matches:
            resource_id = matches[0]["Id"]
            tags = self.success(self.call("appconfig", "list_tags_for_resource", "recover-tags-" + kind,
                                          ResourceArn=self.arn(kind, resource_id)))["Tags"]
            if tags.get(OWNER_KEY) != self.data["owned"]["name"]:
                raise RuntimeError("Recovery ownership tag mismatch")
            self.remember(kind, resource_id)
        else:
            entry["absence_verified"] = True
            self.save()

    def cleanup(self):
        self.cleanup_phase = True
        resources = self.data["owned"]["resources"]
        failures = []
        # Recover the parent first so nested ARNs remain exact on cleanup-only resume.
        for kind in KINDS:
            if kind in resources:
                try:
                    self.recover(kind, resources[kind])
                except Exception as error:
                    failures.append(kind + ": " + str(error))
        for kind in reversed(KINDS):
            entry = resources.get(kind)
            if not entry or "id" not in entry:
                continue
            request = {"application": {"ApplicationId": entry["id"]},
                       "environment": {"EnvironmentId": entry["id"]},
                       "configurationprofile": {"ConfigurationProfileId": entry["id"]},
                       "deploymentstrategy": {"DeploymentStrategyId": entry["id"]}}[kind]
            if kind in ("environment", "configurationprofile"):
                request["ApplicationId"] = entry["create_input"]["ApplicationId"]
            try:
                deleted = self.call("appconfig", "delete_" + METHODS[kind], "delete-" + kind, **request)
                if deleted["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError(deleted["code"])
                absent = self.call("appconfig", "get_" + METHODS[kind], "absence-" + kind, **request)
                entry["absence_verified"] = absent["code"] == "ResourceNotFoundException"
                if not entry["absence_verified"]:
                    raise RuntimeError("Native absence not confirmed")
            except Exception as error:
                failures.append(kind + ": " + str(error))
        self.data["cleanup_failures"] = failures
        self.data["cleanup_verified"] = not failures and all(entry.get("absence_verified") for entry in resources.values())
        self.save()
        if not self.data["cleanup_verified"]:
            raise RuntimeError("Exact-owned cleanup incomplete; resume --cleanup-only: " + str(failures))


class ExtensionCapture(Capture):
    """Separate control-only extension run; preserves the original four-type run."""

    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only:
            self.data["scope"] = "One owned application, one extension with at most two versions, and one association. Inert nonexistent Lambda URI; no role, invocation, deployment, or configuration retrieval."
            self.data["limitations"] = ["Only recorded extension ARN spellings and tag operations measured; no extension execution or IAM claim."]
            self.data["source_urls"] += [
                "https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_CreateExtension.html",
                "https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_CreateExtensionAssociation.html",
                "https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_Action.html",
            ]
            self.data["owned"]["extension"] = {"versions": []}
            self.save()

    def capture(self):
        self.create("application")
        name = self.data["owned"]["name"]
        tags = {OWNER_KEY: name}
        request = {"Name": name, "Description": "Inert tagging control; never invoke",
                   "Actions": {"PRE_START_DEPLOYMENT": [{"Name": "never-invoke",
                                "Uri": f"arn:aws:lambda:{REGION}:{self.account}:function:{name}-absent"}]},
                   "Tags": dict(tags, version="one")}
        extension = self.data["owned"]["extension"]
        extension["create_input"] = request
        self.save()
        first = self.call("appconfig", "create_extension", "create-extension-v1", **request)
        if first["code"] != "Success":
            self.data["admission_blocker"] = first["output"]
            self.data["complete"] = True
            self.save()
            return
        extension.update(id=first["output"]["Id"], versions=[first["output"]["VersionNumber"]])
        self.save()
        second_request = dict(request, LatestVersionNumber=first["output"]["VersionNumber"],
                              Description="Second inert tagging version", Tags=dict(tags, version="two"))
        extension["second_create_input"] = second_request
        self.save()
        second = self.call("appconfig", "create_extension", "create-extension-v2", **second_request)
        candidates = {"v1": first["output"]["Arn"],
                      "unversioned": first["output"]["Arn"].rsplit("/", 1)[0]}
        if second["code"] == "Success":
            if second["output"]["Id"] != extension["id"]:
                raise RuntimeError("Unexpected second extension identity")
            extension["versions"].append(second["output"]["VersionNumber"])
            candidates["v2"] = second["output"]["Arn"]
            self.save()
        association_request = {
            "ExtensionIdentifier": extension["id"], "ExtensionVersionNumber": 1,
            "ResourceIdentifier": self.data["owned"]["resources"]["application"]["arn"],
            "Tags": tags,
        }
        self.data["owned"]["association"] = {"create_input": association_request}
        self.save()
        association = self.call("appconfig", "create_extension_association", "create-association",
                                **association_request)
        if association["code"] == "Success":
            self.data["owned"]["association"].update(id=association["output"]["Id"],
                                                    arn=association["output"]["Arn"])
            candidates["association"] = association["output"]["Arn"]
            self.save()
        self.data["tagging_candidates"] = candidates
        self.save()

        def snapshots(label):
            for spelling, arn in candidates.items():
                self.call("appconfig", "list_tags_for_resource", label + "-" + spelling, ResourceArn=arn)
            self.call("resourcegroupstaggingapi", "get_resources", label + "-rgta",
                      ResourceARNList=list(candidates.values()))

        snapshots("initial")
        for spelling, arn in candidates.items():
            self.call("appconfig", "tag_resource", "native-tag-" + spelling,
                      ResourceArn=arn, Tags={"native-" + spelling: "set"})
            snapshots("after-native-tag-" + spelling)
            self.call("appconfig", "untag_resource", "native-untag-" + spelling,
                      ResourceArn=arn, TagKeys=["native-" + spelling])
            snapshots("after-native-untag-" + spelling)
            self.call("resourcegroupstaggingapi", "tag_resources", "rgta-tag-" + spelling,
                      ResourceARNList=[arn], Tags={"rgta-" + spelling: "set"})
            snapshots("after-rgta-tag-" + spelling)
            self.call("resourcegroupstaggingapi", "untag_resources", "rgta-untag-" + spelling,
                      ResourceARNList=[arn], TagKeys=["rgta-" + spelling])
            snapshots("after-rgta-untag-" + spelling)
        self.data["resource_type_filters"] = {}
        for filter_value in ("appconfig", "appconfig:extension", "appconfig:extensionassociation"):
            self.data["resource_type_filters"][filter_value] = self.discover("filter-" + filter_value, [filter_value])
        self.data["complete"] = True
        self.save()

    def cleanup(self):
        self.cleanup_phase = True
        failures = []
        extension = self.data["owned"].get("extension", {})
        association = self.data["owned"].get("association", {})
        try:
            # Recover successful responses even if interrupted before updating ownership.
            for row in self.data["observations"]:
                if row["code"] != "Success":
                    continue
                if row["operation"] == "CreateExtension":
                    extension["id"] = row["output"]["Id"]
                    version = row["output"]["VersionNumber"]
                    if version not in extension["versions"]:
                        extension["versions"].append(version)
                if row["operation"] == "CreateExtensionAssociation":
                    association["id"] = row["output"]["Id"]
            # Exact-name recovery also covers a lost create response.
            if extension.get("create_input"):
                request = {}
                for page in range(100):
                    output = self.success(self.call("appconfig", "list_extensions", "recover-extension-" + str(page), **request))
                    matches = [item for item in output["Items"] if item["Name"] == self.data["owned"]["name"]]
                    if len(matches) > 1:
                        raise RuntimeError("Ambiguous extension ownership")
                    if matches:
                        item = matches[0]
                        if extension.get("id") not in (None, item["Id"]):
                            raise RuntimeError("Extension ownership changed")
                        extension["id"] = item["Id"]
                        # A lost second-create response can leave version 2 live.
                        for version in range(1, item["VersionNumber"] + 1):
                            if version not in extension["versions"]:
                                extension["versions"].append(version)
                    if not output.get("NextToken"):
                        break
                    request["NextToken"] = output["NextToken"]
                else:
                    raise RuntimeError("Extension recovery pagination exhausted")
            if association.get("create_input") and "id" not in association:
                request = {"ResourceIdentifier": association["create_input"]["ResourceIdentifier"]}
                output = self.success(self.call("appconfig", "list_extension_associations", "recover-association", **request))
                if output.get("NextToken"):
                    raise RuntimeError("Unexpected association recovery pagination")
                matches = [item for item in output["Items"]
                           if item["ExtensionArn"].split("/")[-2] == extension.get("id")]
                if len(matches) > 1:
                    raise RuntimeError("Ambiguous association ownership")
                if matches:
                    association["id"] = matches[0]["Id"]
            self.save()
            if "id" in association:
                row = self.call("appconfig", "delete_extension_association", "delete-association",
                                ExtensionAssociationId=association["id"])
                if row["code"] not in ("Success", "ResourceNotFoundException"):
                    raise RuntimeError(row["code"])
                row = self.call("appconfig", "get_extension_association", "absence-association",
                                ExtensionAssociationId=association["id"])
                if row["code"] != "ResourceNotFoundException":
                    raise RuntimeError("Association absence unverified")
                association["absence_verified"] = True
            if "id" in extension:
                for version in sorted(extension.get("versions", []) or [1], reverse=True):
                    row = self.call("appconfig", "delete_extension", "delete-extension-v" + str(version),
                                    ExtensionIdentifier=extension["id"], VersionNumber=version)
                    if row["code"] not in ("Success", "ResourceNotFoundException"):
                        raise RuntimeError(row["code"])
                    row = self.call("appconfig", "get_extension", "absence-extension-v" + str(version),
                                    ExtensionIdentifier=extension["id"], VersionNumber=version)
                    if row["code"] != "ResourceNotFoundException":
                        raise RuntimeError("Extension absence unverified")
                extension["absence_verified"] = True
        except Exception as error:
            failures.append(str(error))
        super().cleanup()
        self.data["cleanup_failures"].extend(failures)
        self.data["cleanup_verified"] = not self.data["cleanup_failures"]
        self.save()
        if failures:
            raise RuntimeError("Extension cleanup incomplete: " + str(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/resourcegroupstaggingapi/appconfig.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--extensions", action="store_true",
                        help="Run inert extension/association calibration in a separate output ledger")
    args = parser.parse_args()
    capture = (ExtensionCapture if args.extensions else Capture)(args)
    try:
        if not args.cleanup_only:
            capture.capture()
    finally:
        capture.cleanup()
    print(json.dumps({"output": str(args.output), "complete": capture.data["complete"],
                      "cleanup_verified": capture.data["cleanup_verified"]}), flush=True)


if __name__ == "__main__":
    main()
