#!/usr/bin/env python3
"""Capture exact-owned Config tagging; resume durable ledger with --cleanup-only.

Never starts recording or creates a delivery channel. No policies are attached.
Use --cloudtrail-only for read-only request-ID correlation after capture.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

from aws_cli import call as cli_call

OWNER = "stackd-config-tagging-probe"
SOURCES = [
    "https://docs.aws.amazon.com/config/latest/APIReference/API_" + name + ".html"
    for name in ("ListTagsForResource", "TagResource", "UntagResource", "PutConfigRule",
                 "PutConfigurationRecorder", "PutConfigurationAggregator", "PutAggregationAuthorization")
] + [
    "https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_TagResources.html",
    "https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_UntagResources.html",
    "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ResourceGroupsTaggingAPITagUntagSupportedResources.html",
    "https://docs.aws.amazon.com/config/latest/developerguide/log-api-calls.html",
]


def now():
    return datetime.now(timezone.utc).isoformat()


class Capture:
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.session = boto3.Session(region_name=args.regions[0])
        self.config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                             retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30)
        credentials = self.session.get_credentials()
        frozen = credentials.get_frozen_credentials() if credentials else None
        self.secrets = [v for v in (frozen.access_key, frozen.secret_key, frozen.token) if v] if frozen else []
        self.clients = {}
        self.cleaning = False
        if args.cleanup_only or args.cloudtrail_only:
            self.data = json.loads(args.output.read_text())
            if self.data.get("account") != self.account:
                raise RuntimeError("Cleanup ledger account mismatch")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite evidence; use --cleanup-only")
            self.data = {"captured_at": now(), "account": self.account, "source_urls": SOURCES,
                         "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__},
                         "name": "stackd-config-tags-" + uuid.uuid4().hex[:16], "owned": {},
                         "observations": [], "cleanup": [], "complete": False,
                         "cleanup_verified": False, "calibration_gaps": [
                             "IAM condition-key support is official-documentation-only; no IAM policy evaluation probe.",
                             "Cross-account behavior is unmeasured; no unrelated-account authorization or mutation.",
                             "Discovery absence within the bounded polling window does not prove permanent ineligibility.",
                             "No recording, delivery channel, evaluations, or Resource Groups group creation is exercised."]}
        self.save()
        identity = self.require(self.call("sts", "get_caller_identity", "verify-sdk-identity", args.regions[0]))
        env = dict(os.environ, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true", AWS_REGION=args.regions[0],
                   AWS_DEFAULT_REGION=args.regions[0], AWS_MAX_ATTEMPTS="1")
        cli_identity = cli_call("sts", "get-caller-identity", env=env)
        if identity["Account"] != self.account or cli_identity["Arn"] != identity["Arn"]:
            raise RuntimeError("Refusing unexpected native identity")
        self.data["identity"] = identity
        self.data["cli_identity"] = cli_identity
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(self.data, indent=2, default=str) + "\n"
        for secret in self.secrets:
            text = text.replace(secret, "<redacted-credential>")
        text = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "<redacted-access-key-id>", text)
        temporary = self.args.output.with_suffix(".json.tmp")
        with temporary.open("w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.args.output)
        directory = os.open(self.args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def call(self, service, method, case, region=None, **request):
        region = region or self.data["region"]
        key = (service, region)
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=self.config)
        client = self.clients[key]
        row = {"case": case, "at": now(), "service": service, "region": region,
               "operation": client.meta.method_to_api_mapping[method], "input": request}
        self.data["cleanup" if self.cleaning else "observations"].append(row)
        self.save()
        try:
            row.update(code="Success", output=getattr(client, method)(**request))
        except ClientError as error:
            row.update(code=error.response["Error"]["Code"], output=error.response)
        except Exception as error:
            row.update(code="TransportOrClientFailure", failure_type=type(error).__name__)
            raise
        finally:
            self.save()
        print(json.dumps({"case": case, "code": row["code"]}), flush=True)
        return row

    def capture_cloudtrail(self):
        operations = ("PutConfigurationAggregator", "TagResource", "UntagResource")
        targets = {
            row["output"]["ResponseMetadata"]["RequestId"]: row
            for row in self.data["observations"]
            if row.get("service") == "config" and row.get("region") == self.data["region"]
            and row.get("code") == "Success" and row.get("operation") in operations
        }
        if not targets:
            raise RuntimeError("No retained successful Config mutation request IDs")
        times = [datetime.fromisoformat(row["at"]) for row in targets.values()]
        client = self.session.client("cloudtrail", region_name=self.data["region"], config=self.config)
        evidence = self.data.setdefault("cloudtrail", {
            "case": "cloudtrail-config-event-source-request-id-match",
            "source_url": "https://docs.aws.amazon.com/config/latest/developerguide/log-api-calls.html",
            "calls": [], "matches": [], "calibration_gaps": [],
            "retention": "Exact request-ID, operation, region and recipient-account matches only; unrelated events omitted and access key IDs redacted."
        })
        if evidence["source_url"] not in self.data["source_urls"]:
            self.data["source_urls"].append(evidence["source_url"])
        for operation in operations:
            request = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": operation}],
                       "StartTime": min(times) - timedelta(minutes=1),
                       "EndTime": max(times) + timedelta(minutes=1), "MaxResults": 50}
            for page in range(10):
                row = {"case": "cloudtrail-event-source-" + operation + "-" + str(page),
                       "at": now(), "service": "cloudtrail", "operation": "LookupEvents",
                       "region": self.data["region"], "input": dict(request)}
                evidence["calls"].append(row)
                self.save()
                try:
                    time.sleep(0.6)
                    output = client.lookup_events(**request)
                    retained = []
                    for item in output.get("Events", []):
                        event = json.loads(item["CloudTrailEvent"])
                        target = targets.get(event.get("requestID"))
                        if target is None or event.get("eventName") != target["operation"]:
                            continue
                        if event.get("awsRegion") != self.data["region"] or event.get("recipientAccountId") != self.account:
                            continue
                        retained.append(item)
                        evidence["matches"].append({
                            "case": target["case"], "request_id": event["requestID"],
                            "event_id": event["eventID"], "event_source": event["eventSource"],
                            "operation": event["eventName"]
                        })
                    row.update(code="Success", omitted_unmatched_events=len(output.get("Events", [])) - len(retained),
                               output=dict(output, Events=retained))
                except ClientError as error:
                    row.update(code=error.response["Error"]["Code"], output=error.response)
                    evidence["calibration_gaps"].append(operation + ": " + row["code"])
                    break
                finally:
                    self.save()
                if not output.get("NextToken"):
                    break
                request["NextToken"] = output["NextToken"]
            else:
                evidence["calibration_gaps"].append(operation + ": bounded at ten lookup pages")
        matched = {item["request_id"] for item in evidence["matches"]}
        evidence["unmatched_request_ids"] = sorted(set(targets) - matched)
        evidence["observed_event_sources"] = sorted({item["event_source"] for item in evidence["matches"]})
        if evidence["unmatched_request_ids"]:
            evidence["calibration_gaps"].append("Unmatched prior mutations remain uncalibrated; bounded lookup absence is not evidence that CloudTrail omits an operation.")
        self.save()
        print(json.dumps({"case": evidence["case"], "matched_request_ids": len(matched),
                          "observed_event_sources": evidence["observed_event_sources"]}))

    @staticmethod
    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["case"] + ": " + row["code"])
        return row["output"]

    def tags(self, arn, case, **request):
        return self.call("config", "list_tags_for_resource", case, ResourceArn=arn, **request)

    def intent(self, kind, method, request):
        self.data["owned"][kind] = {"intent_at": now(), "method": method, "request": request}
        self.save()
        return self.call("iam" if kind == "role" else "config", method, "create-" + kind, **request)

    def remember(self, kind, arn):
        self.data["owned"][kind]["arn"] = arn
        self.save()

    def baseline(self, region):
        recorders = self.require(self.call("config", "describe_configuration_recorders", "baseline-recorders", region))
        channels = self.require(self.call("config", "describe_delivery_channels", "baseline-channels", region))
        return not recorders.get("ConfigurationRecorders") and not channels.get("DeliveryChannels")

    def create(self):
        safe = None
        for region in self.args.regions:
            if self.baseline(region) and safe is None:
                safe = region
        self.data["region"] = safe or self.args.regions[0]
        self.save()
        name = self.data["name"]
        region = self.data["region"]
        tags = [{"Key": OWNER, "Value": name}, {"Key": "stage", "Value": "created"}]
        # New UUID name; describe explicitly to establish absence before a put/upsert.
        check = self.call("config", "describe_configuration_aggregators", "aggregator-preflight",
                          ConfigurationAggregatorNames=[name])
        if check["code"] != "NoSuchConfigurationAggregatorException":
            raise RuntimeError("Aggregator name absence not established")
        request = {"ConfigurationAggregatorName": name, "AccountAggregationSources": [
            {"AccountIds": [self.account], "AwsRegions": [region], "AllAwsRegions": False}], "Tags": tags}
        output = self.require(self.intent("aggregator", "put_configuration_aggregator", request))
        self.remember("aggregator", output["ConfigurationAggregator"]["ConfigurationAggregatorArn"])
        auths = []
        request = {}
        for page in range(20):
            output = self.require(self.call("config", "describe_aggregation_authorizations", "authorization-preflight", **request))
            auths.extend(output.get("AggregationAuthorizations", []))
            if not output.get("NextToken"):
                break
            request["NextToken"] = output["NextToken"]
        else:
            raise RuntimeError("Authorization preflight pagination bound reached")
        if any(item["AuthorizedAccountId"] == self.account and item["AuthorizedAwsRegion"] == region for item in auths):
            self.data["calibration_gaps"].append("Aggregation authorization native contract documented-only: same-account same-region authorization already exists and was not modified.")
        else:
            output = self.require(self.intent("authorization", "put_aggregation_authorization", {
                "AuthorizedAccountId": self.account, "AuthorizedAwsRegion": region, "Tags": tags}))
            self.remember("authorization", output["AggregationAuthorization"]["AggregationAuthorizationArn"])
        if safe is None:
            self.data["calibration_gaps"].append("Recorder and rule native contracts documented-only: every inspected region had an existing recorder or delivery channel.")
            self.save()
            return
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
            "Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {
            "StringEquals": {"AWS:SourceAccount": self.account}}}]}
        row = self.intent("role", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": tags})
        if row["code"] != "Success":
            self.data["calibration_gaps"].append("Recorder/rule documented-only: exact-owned minimal role creation failed: " + row["code"])
            self.save()
            return
        self.remember("role", row["output"]["Role"]["Arn"])
        time.sleep(10)
        if not self.baseline(region):
            self.data["calibration_gaps"].append("Recorder/rule documented-only: regional singleton appeared during probe; no existing singleton modified.")
            self.save()
            return
        row = self.intent("recorder", "put_configuration_recorder", {"ConfigurationRecorder": {
            "name": name, "roleARN": self.data["owned"]["role"]["arn"], "recordingGroup": {
                "allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": ["AWS::S3::Bucket"]}}, "Tags": tags})
        if row["code"] != "Success":
            self.data["calibration_gaps"].append("Recorder/rule documented-only: stopped recorder creation failed: " + row["code"])
            self.save()
            return
        output = self.require(self.call("config", "describe_configuration_recorders", "created-recorder", ConfigurationRecorderNames=[name]))
        self.remember("recorder", output["ConfigurationRecorders"][0]["arn"])
        self.require(self.call("config", "describe_configuration_recorder_status", "recorder-remains-stopped", ConfigurationRecorderNames=[name]))
        row = self.intent("rule", "put_config_rule", {"ConfigRule": {"ConfigRuleName": name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "REQUIRED_TAGS"},
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "InputParameters": json.dumps({"tag1Key": OWNER})}, "Tags": tags})
        if row["code"] == "Success":
            output = self.require(self.call("config", "describe_config_rules", "created-rule", ConfigRuleNames=[name]))
            self.remember("rule", output["ConfigRules"][0]["ConfigRuleArn"])
        else:
            self.data["calibration_gaps"].append("Rule native contract documented-only: REQUIRED_TAGS rule creation failed: " + row["code"])
        self.save()

    def discover(self, case, filters):
        request = {"TagFilters": [{"Key": OWNER, "Values": [self.data["name"]]}],
                   "ResourceTypeFilters": filters, "ResourcesPerPage": 100}
        found = []
        for page in range(10):
            row = self.call("resourcegroupstaggingapi", "get_resources", case + "-" + str(page), **request)
            if row["code"] != "Success":
                return None
            found.extend(item["ResourceARN"] for item in row["output"].get("ResourceTagMappingList", []))
            if not row["output"].get("PaginationToken"):
                return sorted(found)
            request["PaginationToken"] = row["output"]["PaginationToken"]
        raise RuntimeError("Discovery pagination bound reached")

    def additional_cases(self, arn):
        self.call("config", "tag_resource", "missing-tag-value", ResourceArn=arn,
                  Tags=[{"Key": "missing-value"}])
        self.tags(arn, "after-missing-tag-value")
        self.call("config", "untag_resource", "remove-missing-value-probe",
                  ResourceArn=arn, TagKeys=["missing-value"])
        wrong_service = f"arn:aws:sns:{self.data['region']}:{self.account}:{self.data['name']}"
        self.tags(wrong_service, "wrong-service-arn-list")
        self.call("config", "tag_resource", "wrong-service-arn-tag",
                  ResourceArn=wrong_service, Tags=[{"Key": "wrong-service", "Value": "value"}])

    def capture(self):
        self.create()
        entries = {kind: entry for kind, entry in self.data["owned"].items() if kind != "role" and "arn" in entry}
        arns = sorted(entry["arn"] for entry in entries.values())
        for kind, entry in entries.items():
            arn = entry["arn"]
            self.tags(arn, "create-tags-" + kind)
            request = dict(entry["request"], Tags=[{"Key": "stage", "Value": "put-update"}, {"Key": "put-only", "Value": "new"}])
            self.call("config", entry["method"], "update-put-tags-" + kind, **request)
            self.tags(arn, "after-put-update-" + kind)
            self.call("config", "tag_resource", "native-tag-" + kind, ResourceArn=arn, Tags=[{"Key": "stage", "Value": "native"}, {"Key": "native", "Value": "roundtrip"}])
            self.tags(arn, "after-native-tag-" + kind)
            self.call("config", "untag_resource", "native-untag-" + kind, ResourceArn=arn, TagKeys=["native", "absent"])
            self.tags(arn, "after-native-untag-" + kind)
        self.additional_cases(entries["aggregator"]["arn"])
        arn = entries["aggregator"]["arn"]
        for case, tags in [("duplicate-keys", [{"Key": "duplicate", "Value": "first"}, {"Key": "duplicate", "Value": "last"}]),
                           ("reserved-key", [{"Key": "aws:reserved", "Value": "value"}])]:
            self.call("config", "tag_resource", case, ResourceArn=arn, Tags=tags)
            self.tags(arn, "after-" + case)
        self.call("config", "untag_resource", "remove-duplicate-probe", ResourceArn=arn, TagKeys=["duplicate"])
        self.call("config", "tag_resource", "fifty-tags", ResourceArn=arn, Tags=[{"Key": "boundary-" + str(i), "Value": "value"} for i in range(48)])
        before = self.require(self.tags(arn, "before-overflow"))
        self.call("config", "tag_resource", "overflow-atomic", ResourceArn=arn, Tags=[{"Key": "stage", "Value": "must-not-change"}, {"Key": "overflow", "Value": "new"}])
        after = self.require(self.tags(arn, "after-overflow"))
        self.data["overflow_atomic_unchanged"] = before.get("Tags") == after.get("Tags")
        request = {"Limit": 1}
        paged = []
        for page in range(55):
            row = self.tags(arn, "tag-page-" + str(page), **request)
            if row["code"] != "Success":
                break
            paged.extend(row["output"].get("Tags", []))
            if not row["output"].get("NextToken"):
                break
            request["NextToken"] = row["output"]["NextToken"]
        else:
            raise RuntimeError("Tag pagination bound reached")
        self.data["paginated_tags"] = paged
        for limit in (0, 50, 51, 100, 101):
            self.tags(arn, "tag-limit-" + str(limit), Limit=limit)
        self.tags(arn, "invalid-next-token", NextToken="not-a-valid-token")
        missing = arn.rsplit("/", 1)[0] + "/config-aggregator-000000000000"
        self.tags(missing, "missing-arn-list")
        self.call("config", "tag_resource", "missing-arn-tag", ResourceArn=missing, Tags=[{"Key": "missing", "Value": "value"}])
        self.call("config", "untag_resource", "missing-arn-untag", ResourceArn=missing, TagKeys=["missing"])
        other_region = next(region for region in ("us-east-2", "us-west-2") if region != self.data["region"])
        self.call("config", "list_tags_for_resource", "cross-region-native-list", other_region, ResourceArn=arn)
        self.call("resourcegroupstaggingapi", "get_resources", "cross-region-explicit", other_region, ResourceARNList=arns)
        self.call("config", "untag_resource", "clear-boundary-tags", ResourceArn=arn, TagKeys=["boundary-" + str(i) for i in range(48)])
        deadline = time.monotonic() + self.args.discovery_seconds
        attempt = 0
        while True:
            found = self.discover("service-discovery-" + str(attempt), ["config"])
            if found == arns or time.monotonic() >= deadline:
                break
            attempt += 1
            time.sleep(10)
        self.data["resource_type_filters"] = {}
        for value in ("config", "config:config-rule", "config:config-aggregator", "config:aggregation-authorization", "config:configuration-recorder", "config:recorder"):
            self.data["resource_type_filters"][value] = self.discover("filter-" + value, [value])
        for method, case, extra in [("tag_resources", "shared-tag", {"Tags": {"shared": "roundtrip"}}),
                                     ("untag_resources", "shared-untag", {"TagKeys": ["shared"]})]:
            self.call("resourcegroupstaggingapi", method, case, ResourceARNList=arns, **extra)
            for kind, entry in entries.items():
                self.tags(entry["arn"], "after-" + case + "-" + kind)
        self.call("resourcegroupstaggingapi", "get_resources", "explicit-owned", ResourceARNList=arns)
        for kind, entry in entries.items():
            current = self.require(self.tags(entry["arn"], "before-terminal-untag-" + kind))
            keys = [tag["Key"] for tag in current.get("Tags", [])]
            if keys:
                self.call("config", "untag_resource", "terminal-untag-" + kind, ResourceArn=entry["arn"], TagKeys=keys)
            self.tags(entry["arn"], "empty-tags-" + kind)
        self.call("resourcegroupstaggingapi", "get_resources", "explicit-previously-tagged-empty", ResourceARNList=arns)
        self.data["complete"] = True
        self.save()

    def cleanup(self):
        self.cleaning = True
        name = self.data["name"]
        failures = []
        for kind in ("rule", "recorder", "authorization", "aggregator", "role"):
            if kind not in self.data["owned"]:
                continue
            try:
                service = "iam" if kind == "role" else "config"
                method, request, absent, field = {
                    "rule": ("describe_config_rules", {"ConfigRuleNames": [name]}, "NoSuchConfigRuleException", "ConfigRules"),
                    "recorder": ("describe_configuration_recorders", {"ConfigurationRecorderNames": [name]}, "NoSuchConfigurationRecorderException", "ConfigurationRecorders"),
                    "aggregator": ("describe_configuration_aggregators", {"ConfigurationAggregatorNames": [name]}, "NoSuchConfigurationAggregatorException", "ConfigurationAggregators"),
                    "authorization": ("describe_aggregation_authorizations", {}, "", "AggregationAuthorizations"),
                    "role": ("get_role", {"RoleName": name}, "NoSuchEntity", "Role"),
                }[kind]

                def present(case):
                    row = self.call(service, method, case, **request)
                    if row["code"] == absent:
                        return False
                    result = self.require(row)
                    if kind == "authorization":
                        items = result.get(field, [])
                        token = result.get("NextToken")
                        for page in range(20):
                            if not token:
                                break
                            result = self.require(self.call(service, method, case + "-page", NextToken=token))
                            items += result.get(field, [])
                            token = result.get("NextToken")
                        if token:
                            raise RuntimeError("Cleanup authorization pagination bound")
                        return any(item["AuthorizedAccountId"] == self.account and item["AuthorizedAwsRegion"] == self.data["region"] for item in items)
                    if kind == "role" and result.get(field) and "arn" not in self.data["owned"][kind]:
                        tags = result[field].get("Tags", [])
                        if not any(tag["Key"] == OWNER and tag["Value"] == name for tag in tags):
                            raise RuntimeError("Role ownership could not be recovered")
                    return bool(result.get(field))

                if present("cleanup-preflight-" + kind):
                    deletion, parameters = {
                        "rule": ("delete_config_rule", {"ConfigRuleName": name}),
                        "recorder": ("delete_configuration_recorder", {"ConfigurationRecorderName": name}),
                        "aggregator": ("delete_configuration_aggregator", {"ConfigurationAggregatorName": name}),
                        "authorization": ("delete_aggregation_authorization", {"AuthorizedAccountId": self.account, "AuthorizedAwsRegion": self.data["region"]}),
                        "role": ("delete_role", {"RoleName": name}),
                    }[kind]
                    self.require(self.call(service, deletion, "delete-" + kind, **parameters))
                for attempt in range(12):
                    if not present("verify-absent-" + kind + "-" + str(attempt)):
                        self.data["owned"][kind]["absence_verified"] = True
                        self.save()
                        break
                    time.sleep(5)
                else:
                    raise RuntimeError("Exact-owned resource still present: " + kind)
            except Exception as error:
                failures.append(kind + ": " + str(error))
        self.data["cleanup_failures"] = failures
        self.data["cleanup_verified"] = not failures
        self.save()
        if failures:
            raise RuntimeError("Cleanup incomplete; resume --cleanup-only: " + str(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--regions", nargs="+", default=["us-west-2", "us-east-2"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/configservice/tagging.json"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--cloudtrail-only", action="store_true")
    parser.add_argument("--discovery-seconds", type=int, default=60)
    args = parser.parse_args()
    capture = Capture(args)
    if args.cloudtrail_only:
        capture.capture_cloudtrail()
        return
    try:
        if not args.cleanup_only:
            capture.capture()
    except Exception as error:
        capture.data["failure"] = str(error)
        capture.save()
        raise
    finally:
        capture.cleanup()
    print(json.dumps({"capture": str(args.output), "complete": capture.data["complete"],
                      "cleanup_verified": capture.data["cleanup_verified"]}))


if __name__ == "__main__":
    main()
