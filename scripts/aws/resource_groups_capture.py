#!/usr/bin/env python3
"""Capture native Resource Groups contracts; only mutate unique exact-owned resources.

Run with Python + boto3, from any directory. The authorized account is pinned;
AWS endpoint overrides are disabled. No account lifecycle, IAM, AppRegistry,
capacity reservation, host, firewall, or other standing settings are changed.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


SOURCES = [
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_CreateGroup.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_ResourceQuery.html",
    "https://docs.aws.amazon.com/ARG/latest/userguide/gettingstarted-query.html",
    "https://docs.aws.amazon.com/ARG/latest/userguide/about-slg-types.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_GroupResources.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_UngroupResources.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_ListGroupingStatuses.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_StartTagSyncTask.html",
    "https://docs.aws.amazon.com/servicecatalog/latest/arguide/app-tag-sync.html",
    "https://docs.aws.amazon.com/network-firewall/latest/developerguide/resource-groups.html",
    "https://docs.aws.amazon.com/network-firewall/latest/developerguide/resource-group-creating.html",
    "https://docs.aws.amazon.com/ARG/latest/userguide/resource-groups-gle-availability-change.html",
    "https://docs.aws.amazon.com/servicecatalog/latest/arguide/app-registry-availability-change.html",
    "https://docs.aws.amazon.com/ARG/latest/APIReference/API_GroupFilter.html",
]


def query(filters, types=None):
    return {"Type": "TAG_FILTERS_1_0", "Query": json.dumps({
        "ResourceTypeFilters": types if types is not None else ["AWS::AllSupported"],
        "TagFilters": filters}, separators=(",", ":"))}


def capture_audit(session, config, identity, region, path):
    # Reuse the repository's bounded read-only CloudTrail collector.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cloudtrail_events import CollectionError, collect_history

    root = Path(__file__).resolve().parents[2] / ".stackd/probes/resourcegroups"
    fixture_names = ("native.json", "native-query-boundaries.json", "native-attributes.json")
    captures = [json.loads((root / filename).read_text()) for filename in fixture_names]
    for capture in captures:
        if capture["identity"]["Account"] != identity["Account"] or capture["region"] != region:
            raise RuntimeError("Audit fixture scope differs from the verified caller/region")
    prefixes = [capture["owned"]["prefix"] for capture in captures]

    def exact_owned(value):
        encoded = json.dumps(value, default=str)
        return any(prefix in encoded for prefix in prefixes)

    requests = {}
    for filename, capture in zip(fixture_names, captures):
        for row in capture["observations"] + capture["cleanup"]:
            if row["service"] == "resource-groups" and exact_owned(row["input"]):
                requests[row["request_id"]] = filename + ":" + row["case"]
    start = min(datetime.datetime.fromisoformat(capture["captured_at"]) for capture in captures)
    end = datetime.datetime.now(datetime.timezone.utc)
    client = session.client("cloudtrail", config=config)
    failure = None
    try:
        collection = collect_history(
            lambda request: client.lookup_events(**request), requests,
            start_time=start, end_time=end,
            event_sources=("resourcegroups.amazonaws.com", "resource-groups.amazonaws.com"),
            max_pages=20, rounds=1, related=exact_owned)
    except CollectionError as error:
        collection = error.result
        failure = error
    # Exact request-ID matches are useful joins, but cannot bypass prefix scoping.
    collection["events"] = [row for row in collection["events"] if exact_owned(row["event"])]
    observed = {row["event"].get("requestID") for row in collection["events"]}
    collection["missing_request_ids"] = [key for key in requests if key not in observed]
    collection["missing_calls"] = [requests[key] for key in collection["missing_request_ids"]]

    def redact(value):
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()
                    if key.lower() not in ("accesskeyid", "secretaccesskey", "sessiontoken",
                                           "authorization", "credentials")}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    fixture = {
        "captured_at": end.isoformat(), "region": region, "identity": identity,
        "sources": [
            "https://docs.aws.amazon.com/ARG/latest/userguide/security_logging-monitoring.html",
            "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html",
        ],
        "scope": "Read-only CloudTrail history. Only events matching the exact prefixes of the three retained native captures are retained; unrelated event payloads are discarded.",
        "prefixes": prefixes, "input_fixtures": list(fixture_names),
        "redaction": "Credential fields, including lookup AccessKeyId and event userIdentity.accessKeyId, are removed recursively. Native event fields otherwise remain unchanged.",
        "absence_boundary": "Missing/late records are not observed within this bounded lookup; they do not establish that AWS omits those events.",
        "collection": collection,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(fixture), indent=2, default=str) + "\n")
    print(json.dumps({"fixture": str(path), "events": len(collection["events"]),
                      "missing_request_ids": len(collection["missing_request_ids"]),
                      "lookup_pages": len(collection["pages"]), "partial": collection["partial"]}))
    if failure:
        raise failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--selection-wait", type=int, default=180)
    parser.add_argument("--query-boundaries", action="store_true",
                        help="Capture additional query/stack/filter admission without repeating the full probe")
    parser.add_argument("--attributes", action="store_true",
                        help="Capture ordinary-group application attributes and declared-type filter admission")
    parser.add_argument("--audit", action="store_true",
                        help="Read CloudTrail history for the exact prefixes in the three retained native captures")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output is None:
        suffix = "-audit" if args.audit else "-attributes" if args.attributes else "-query-boundaries" if args.query_boundaries else ""
        args.output = Path(__file__).resolve().parents[2] / (".stackd/probes/resourcegroups/native" + suffix + ".json")
    os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
    session = boto3.Session(region_name=args.region)
    config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                    retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=40)
    clients = {s: session.client(s, config=config) for s in
               ("sts", "resource-groups", "s3", "sqs", "cloudformation")}
    identity = clients["sts"].get_caller_identity()
    if identity["Account"] != args.account:
        raise RuntimeError("Only the authorized native account may be probed")
    if args.audit:
        capture_audit(session, config, identity, args.region, args.output)
        return
    account = identity["Account"]
    name = "stackd-rg-" + uuid.uuid4().hex[:12]
    owner = {"Key": "stackd-rg-probe", "Values": [name]}
    tags = {"stackd-rg-probe": name}
    fixture = {
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": args.region, "identity": identity, "sources": SOURCES,
        "sdk": {"boto3": boto3.__version__, "resource_groups_api":
                clients["resource-groups"].meta.service_model.api_version},
        "scope": "Two empty S3 buckets, two SQS queues, empty resource groups and one tiny SQS CloudFormation stack; unique ownership; no account setting changes.",
        "owned": {"prefix": name, "resources": [], "groups": [], "stack": None},
        "observations": [], "cleanup": [], "selection": [],
        "unavailable_dependencies": [
            "No AppRegistry-managed application or Resource Groups application catalog is provisioned; successful application/tag-sync enrollment is not claimed.",
            "No service-assumable tagging role is created; tag-sync probes use an exact-owned nonexistent role ARN, never an unrelated role.",
            "No EC2 Capacity Reservation, dedicated host, EC2 instance or Network Firewall rule is provisioned; positive specialty-resource association and network resolution are unobserved.",
            "Account lifecycle-events setting is read only; no PutAccountSettings call is made.",
        ],
    }
    groups, buckets, queues, tasks = [], [], [], []
    stack = None
    cleanup_phase = False

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(fixture, indent=2, default=str) + "\n")

    def call(service, operation, case, **request):
        row = {"case": case, "service": service, "operation": operation,
               "input": request, "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            response = getattr(clients[service], operation)(**request)
            row["code"] = "Success"
        except ClientError as error:
            response = error.response
            row["code"] = response.get("Error", {}).get("Code")
        metadata = response.pop("ResponseMetadata", {})
        row.update(http_status=metadata.get("HTTPStatusCode"),
                   request_id=metadata.get("RequestId"), output=response)
        fixture["cleanup" if cleanup_phase else "observations"].append(row)
        save()
        print(json.dumps({k: row[k] for k in ("case", "code", "request_id")}), flush=True)
        return row

    def rg(operation, case, **request):
        return call("resource-groups", operation, case, **request)

    def require(row):
        if row["code"] != "Success":
            raise RuntimeError(row["case"] + ": " + str(row["output"]))
        return row["output"]

    def create(suffix, **request):
        row = rg("create_group", suffix, Name=name + "-" + suffix, Tags=tags, **request)
        if row["code"] == "Success":
            arn = row["output"]["Group"]["GroupArn"]
            groups.append(arn)
            fixture["owned"]["groups"].append(arn)
            save()
            return arn
        return None

    def page(operation, case, **request):
        results = []
        for index in range(100):
            row = rg(operation, case + "-page-" + str(index), **request)
            results.append(row)
            token = row["output"].get("NextToken")
            if row["code"] != "Success" or not token:
                return results
            request["NextToken"] = token
        raise RuntimeError("Pagination did not terminate")

    def select(case, filters, expected, types=None):
        q = query(filters, types)
        rows = page("search_resources", case, ResourceQuery=q, MaxResults=1)
        actual = sorted(item["ResourceArn"] for row in rows
                        for item in row["output"].get("ResourceIdentifiers", []))
        fixture["selection"].append({"case": case, "expected": sorted(expected), "actual": actual,
                                     "matches": actual == sorted(expected),
                                     "request_ids": [row["request_id"] for row in rows]})
        save()

    save()
    try:
        rg("get_account_settings", "account-settings-read-only")
        if args.attributes:
            fixture["scope"] = "Only uniquely named empty tag-query groups; application-attribute admission and group filters; no account setting changes."
            resource_query = query([owner], ["AWS::S3::Bucket"])
            attributes = {"DisplayName": name + "-display", "Owner": name + "-owner", "Criticality": 5}
            for field, value in attributes.items():
                create("create-" + field.lower(), ResourceQuery=resource_query, **{field: value})
            group = create("attribute-target", ResourceQuery=resource_query)
            if group is None:
                raise RuntimeError("Attribute target group creation failed")
            for field, value in attributes.items():
                rg("update_group", "update-" + field.lower(), Group=group, **{field: value})
            rg("get_group", "ordinary-group-after-attributes", Group=group)
            for filter_name, field in (("display-name", "DisplayName"), ("owner", "Owner"), ("criticality", "Criticality")):
                page("list_groups", "filter-" + filter_name, MaxResults=50,
                     Filters=[{"Name": filter_name, "Values": [str(attributes[field])]}])
            rg("list_group_resources", "member-filter-outside-query-types", Group=group,
               Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}])
            return
        if args.query_boundaries:
            fixture["scope"] = "Empty exact-owned query groups and one tiny SQS CloudFormation stack; no standing account settings changed."
            boundary_queries = [
                ("duplicate-resource-types", {"ResourceTypeFilters": ["AWS::S3::Bucket", "AWS::S3::Bucket"], "TagFilters": [owner]}),
                ("lower-camel-query-fields", {"resourceTypeFilters": ["AWS::S3::Bucket"], "tagFilters": [{"key": owner["Key"], "values": owner["Values"]}]}),
                ("upper-query-fields", {"RESOURCETYPEFILTERS": ["AWS::S3::Bucket"], "TAGFILTERS": [{"KEY": owner["Key"], "VALUES": owner["Values"]}]}),
                ("mixed-query-fields", {"ResourceTypeFilters": ["AWS::S3::Bucket"], "TagFilters": [{"key": owner["Key"], "values": owner["Values"]}]}),
            ]
            for suffix, raw in boundary_queries:
                create(suffix, ResourceQuery={"Type": "TAG_FILTERS_1_0", "Query": json.dumps(raw)})
            absent_arn = f"arn:aws:cloudformation:{args.region}:{account}:stack/{name}-absent/{uuid.uuid4()}"
            for suffix, identifier in (("empty-stack-identifier", ""), ("nonexistent-stack-arn", absent_arn)):
                stack_query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
                    "ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": identifier})}
                rg("search_resources", suffix, ResourceQuery=stack_query)
                create(suffix, ResourceQuery=stack_query)
            absent_group = f"arn:aws:resource-groups:{args.region}:{account}:group/{name}-absent"
            for suffix, filters in (
                ("missing-name", [{"GroupName": name + "-absent"}]),
                ("missing-arn", [{"GroupArn": absent_group}]),
                ("empty-filter", [{}]),
                ("both-identifiers", [{"GroupName": name + "-absent", "GroupArn": absent_group}]),
            ):
                rg("list_tag_sync_tasks", "tag-sync-list-" + suffix, Filters=filters)
            template = {"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {
                "QueueName": name + "-stack-queue", "Tags": [{"Key": owner["Key"], "Value": name}]}}}}
            output = require(call("cloudformation", "create_stack", "create-boundary-stack",
                                  StackName=name + "-stack", TemplateBody=json.dumps(template),
                                  Tags=[{"Key": owner["Key"], "Value": name}]))
            stack = output["StackId"]
            fixture["owned"]["stack"] = stack
            save()
            stack_query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
                "ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": stack})}
            call("cloudformation", "describe_stacks", "stack-before-early-search", StackName=stack)
            rg("search_resources", "stack-create-in-progress-search", ResourceQuery=stack_query)
            create("stack-query", ResourceQuery=stack_query)
            for attempt in range(48):
                row = call("cloudformation", "describe_stacks", "boundary-stack-ready-" + str(attempt), StackName=stack)
                status = row["output"].get("Stacks", [{}])[0].get("StackStatus", "")
                if not status.endswith("IN_PROGRESS"):
                    break
                time.sleep(5)
            rg("search_resources", "boundary-stack-ready-search", ResourceQuery=stack_query)
            return
        create("no-query-or-configuration")
        rg("get_group", "missing-group-identifier")
        for operation in ("get_group", "get_group_query", "get_group_configuration", "delete_group"):
            rg(operation, operation + "-missing-name", Group=name + "-absent")
        # Seed independent owners before querying the asynchronously populated index.
        arns = []
        for index in range(4):
            resource_name = name + "-" + str(index)
            resource_tags = dict(tags, tier="silver" if index == 2 else "gold")
            if index != 3:
                resource_tags.update(stage="blue" if index == 1 else "red")
                resource_tags[name + "-present"] = "value"
            if index in (0, 2):
                resource_tags["empty"] = ""
            if index < 2:
                request = {"Bucket": resource_name}
                if args.region != "us-east-1":
                    request["CreateBucketConfiguration"] = {"LocationConstraint": args.region}
                require(call("s3", "create_bucket", "create-bucket-" + str(index), **request))
                buckets.append(resource_name)
                arn = "arn:aws:s3:::" + resource_name
                require(call("s3", "put_bucket_tagging", "tag-bucket-" + str(index),
                             Bucket=resource_name, Tagging={"TagSet": [
                                 {"Key": k, "Value": v} for k, v in resource_tags.items()]}))
            else:
                output = require(call("sqs", "create_queue", "create-queue-" + str(index),
                                      QueueName=resource_name, tags=resource_tags))
                queues.append((resource_name, output["QueueUrl"]))
                arn = f"arn:aws:sqs:{args.region}:{account}:" + resource_name
            arns.append(arn)
            fixture["owned"]["resources"].append({"arn": arn, "tags": resource_tags})
            save()

        base_query = query([owner])
        tag_group = create("tag-query", ResourceQuery=base_query, Description="owned native capture")
        if tag_group is None:
            raise RuntimeError("Tag query group creation failed")
        rg("create_group", "duplicate-name", Name=name + "-tag-query", ResourceQuery=base_query)
        rg("get_group", "get-by-name", GroupName=name + "-tag-query")
        rg("get_group", "get-by-arn", Group=tag_group)
        rg("get_group", "conflicting-identifiers", Group=tag_group, GroupName=name + "-absent")
        rg("get_group_configuration", "query-group-configuration", Group=tag_group)
        rg("get_group_query", "query-roundtrip", Group=tag_group)
        rg("update_group", "description-update", Group=tag_group, Description="updated")
        rg("update_group", "description-clear", Group=tag_group, Description="")
        rg("tag", "group-tags", Arn=tag_group, Tags={"roundtrip": "", "stage": "red"})
        rg("get_tags", "group-tags-read", Arn=tag_group)
        rg("untag", "group-untag-missing", Arn=tag_group, Keys=["roundtrip", "absent"])
        rg("get_tags", "group-tags-after-untag", Arn=tag_group)
        rg("tag", "group-reserved-tag", Arn=tag_group, Tags={"aws:reserved": "no"})
        rg("group_resources", "query-group-add", Group=tag_group, ResourceArns=arns[:1])
        rg("ungroup_resources", "query-group-remove", Group=tag_group, ResourceArns=arns[:1])
        rg("list_grouping_statuses", "query-group-statuses", Group=tag_group)

        generic = "AWS::ResourceGroups::Generic"
        capacity = [{"Type": "AWS::EC2::CapacityReservationPool"}, {"Type": generic,
                    "Parameters": [{"Name": "allowed-resource-types", "Values": ["AWS::EC2::CapacityReservation"]}]}]
        configs = [
            ("generic-empty", [{"Type": generic}]),
            ("generic-s3", [{"Type": generic, "Parameters": [{"Name": "allowed-resource-types", "Values": ["AWS::S3::Bucket"]}]}]),
            ("generic-capacity", [capacity[1]]),
            ("generic-unknown-param", [{"Type": generic, "Parameters": [{"Name": "unknown", "Values": ["x"]}]}]),
            ("unknown-config", [{"Type": "AWS::Stackd::Unsupported"}]),
            ("capacity-alone", capacity[:1]),
            ("capacity-pool", capacity),
            ("capacity-invalid-param", [{"Type": "AWS::EC2::CapacityReservationPool", "Parameters": [{"Name": "reservation-type", "Values": ["invalid"]}]}, capacity[1]]),
            ("appregistry-application", [{"Type": "AWS::AppRegistry::Application"}]),
            ("appregistry-stack", [{"Type": "AWS::CloudFormation::Stack"}]),
            ("application-group", [{"Type": "AWS::ResourceGroups::ApplicationGroup"}]),
            ("host-missing-params", [{"Type": "AWS::EC2::HostManagement"}]),
            ("network-without-query", [{"Type": "AWS::NetworkFirewall::RuleGroup"}]),
        ]
        for suffix, configuration in configs:
            group = create(suffix, Configuration=configuration)
            if group:
                rg("get_group_configuration", suffix + "-configuration", Group=group)
                rg("get_group_query", suffix + "-query", Group=group)
                rg("group_resources", suffix + "-add-ineligible", Group=group, ResourceArns=arns[:1])
                rg("ungroup_resources", suffix + "-remove-unassociated", Group=group, ResourceArns=arns[:1])
                rg("list_group_resources", suffix + "-members", Group=group)
                rg("list_grouping_statuses", suffix + "-statuses", Group=group)
                if suffix == "capacity-pool":
                    missing_cr = f"arn:aws:ec2:{args.region}:{account}:capacity-reservation/cr-00000000000000000"
                    rg("group_resources", "capacity-add-nonexistent", Group=group, ResourceArns=[missing_cr])
                    rg("ungroup_resources", "capacity-remove-nonexistent", Group=group, ResourceArns=[missing_cr])
                    rg("put_group_configuration", "capacity-put-identical", Group=group, Configuration=capacity)
                    rg("put_group_configuration", "capacity-put-empty", Group=group, Configuration=[])
                    rg("get_group_configuration", "capacity-after-put-empty", Group=group)
        for suffix, types in (("network-instance", ["AWS::EC2::Instance"]),
                              ("network-s3", ["AWS::S3::Bucket"]),
                              ("network-all", ["AWS::AllSupported"])):
            group = create(suffix, Configuration=[{"Type": "AWS::NetworkFirewall::RuleGroup"}],
                           ResourceQuery=query([owner], types))
            if group:
                rg("get_group_configuration", suffix + "-configuration", Group=group)
                rg("group_resources", suffix + "-manual-add", Group=group, ResourceArns=arns[:1])
                rg("list_group_resources", suffix + "-members", Group=group)
        rg("put_group_configuration", "query-put-generic", Group=tag_group, Configuration=[{"Type": generic}])

        missing_role = f"arn:aws:iam::{account}:role/{name}-absent"
        sync_inputs = [
            ("tag-sync-ordinary-group", {"TagKey": "stackd-rg-probe", "TagValue": name}),
            ("tag-sync-missing-selector", {}),
            ("tag-sync-missing-value", {"TagKey": "stackd-rg-probe"}),
            ("tag-sync-query-and-tag", {"ResourceQuery": base_query, "TagKey": "stackd-rg-probe", "TagValue": name}),
            ("tag-sync-query", {"ResourceQuery": base_query}),
        ]
        for case, request in sync_inputs:
            row = rg("start_tag_sync_task", case, Group=tag_group, RoleArn=missing_role, **request)
            if row["code"] == "Success":
                tasks.append(row["output"]["TaskArn"])
        rg("list_tag_sync_tasks", "tag-sync-list-ordinary-group", Filters=[{"GroupArn": tag_group}])
        missing_task = f"arn:aws:resource-groups:{args.region}:{account}:group/{name}/{'0' * 26}/tag-sync-task/{'0' * 26}"
        rg("get_tag_sync_task", "tag-sync-task-not-found", TaskArn=missing_task)
        rg("cancel_tag_sync_task", "tag-sync-cancel-not-found", TaskArn=missing_task)
        rg("list_grouping_statuses", "grouping-statuses-not-found", Group=name + "-absent")

        # Invalid queries are submitted through CreateGroup, not broad inventory searches.
        invalid_queries = [
            ("query-invalid-json", "{"), ("query-array", "[]"),
            ("query-empty-object", "{}"),
            ("query-missing-types", json.dumps({"TagFilters": [owner]})),
            ("query-empty-types", json.dumps({"ResourceTypeFilters": [], "TagFilters": [owner]})),
            ("query-unknown-type", json.dumps({"ResourceTypeFilters": ["AWS::Stackd::Missing"], "TagFilters": [owner]})),
            ("query-all-plus-type", json.dumps({"ResourceTypeFilters": ["AWS::AllSupported", "AWS::S3::Bucket"], "TagFilters": [owner]})),
            ("query-empty-filters", json.dumps({"ResourceTypeFilters": ["AWS::S3::Bucket"], "TagFilters": []})),
            ("query-empty-key", json.dumps({"ResourceTypeFilters": ["AWS::S3::Bucket"], "TagFilters": [{"Key": ""}]})),
            ("query-unknown-field", json.dumps({"ResourceTypeFilters": ["AWS::S3::Bucket"], "TagFilters": [owner], "Unknown": True})),
        ]
        for suffix, raw in invalid_queries:
            create(suffix, ResourceQuery={"Type": "TAG_FILTERS_1_0", "Query": raw})
        create("query-unknown-version", ResourceQuery={"Type": "TAG_FILTERS_2_0", "Query": base_query["Query"]})
        rg("search_resources", "search-invalid-token", ResourceQuery=base_query, NextToken="invalid")
        rg("search_resources", "search-zero-limit", ResourceQuery=base_query, MaxResults=0)
        rg("list_group_resources", "list-invalid-filter", Group=tag_group, Filters=[{"Name": "bad", "Values": ["x"]}])

        deadline = time.monotonic() + args.selection_wait
        for attempt in range(1 + args.selection_wait // 5):
            row = rg("search_resources", "index-readiness-" + str(attempt), ResourceQuery=base_query)
            found = {r["ResourceArn"] for r in row["output"].get("ResourceIdentifiers", [])}
            if set(arns + groups).issubset(found) or time.monotonic() >= deadline:
                fixture["index_complete"] = set(arns + groups).issubset(found)
                break
            time.sleep(5)
        select("selection-owner", [owner], arns + groups)
        select("selection-key-only", [owner, {"Key": name + "-present"}], arns[:3])
        select("selection-empty-values", [owner, {"Key": "stage", "Values": []}], arns[:3] + [tag_group])
        select("selection-empty-string", [owner, {"Key": "empty", "Values": [""]}], [arns[0], arns[2]])
        select("selection-values-or", [owner, {"Key": "stage", "Values": ["red", "blue"]}], arns[:3] + [tag_group])
        select("selection-keys-and", [owner, {"Key": "stage", "Values": ["red"]}, {"Key": "tier", "Values": ["gold"]}], arns[:1])
        select("selection-case-sensitive", [owner, {"Key": "stage", "Values": ["RED"]}], [])
        select("selection-type-s3", [owner], arns[:2], ["AWS::S3::Bucket"])
        select("selection-type-union", [owner], arns, ["AWS::S3::Bucket", "AWS::SQS::Queue"])
        select("selection-duplicate-key-last-wins", [owner, {"Key": "stage", "Values": ["red"]}, {"Key": "stage", "Values": ["blue"]}], arns[1:2])
        page("list_group_resources", "group-members", Group=tag_group, MaxResults=1)
        rg("list_group_resources", "group-filter-sqs", Group=tag_group, Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}])
        changed = query([owner, {"Key": "stage", "Values": ["blue"]}])
        rg("update_group_query", "query-update", Group=tag_group, ResourceQuery=changed)
        rg("get_group_query", "query-after-update", Group=tag_group)
        rg("list_group_resources", "members-after-query-update", Group=tag_group)
        rg("update_group_query", "query-update-invalid", Group=tag_group,
           ResourceQuery={"Type": "TAG_FILTERS_1_0", "Query": "{"})
        rg("get_group_query", "query-after-invalid-update", Group=tag_group)
        page("list_groups", "groups-pagination", MaxResults=1, Filters=[{"Name": "resource-type", "Values": ["AWS::SQS::Queue"]}])

        template = {"Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": {
            "QueueName": name + "-stack-queue", "Tags": [{"Key": "stackd-rg-probe", "Value": name}]}}}}
        row = call("cloudformation", "create_stack", "create-tiny-stack", StackName=name + "-stack",
                   TemplateBody=json.dumps(template), Tags=[{"Key": "stackd-rg-probe", "Value": name}])
        if row["code"] == "Success":
            stack = row["output"]["StackId"]
            fixture["owned"]["stack"] = stack
            save()
            for attempt in range(48):
                status_row = call("cloudformation", "describe_stacks", "stack-ready-" + str(attempt), StackName=stack)
                status = status_row["output"].get("Stacks", [{}])[0].get("StackStatus", "")
                if not status.endswith("IN_PROGRESS"):
                    break
                time.sleep(5)
            call("cloudformation", "list_stack_resources", "stack-owned-resources", StackName=stack)
            stack_query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
                "ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": stack})}
            rg("search_resources", "stack-search", ResourceQuery=stack_query)
            stack_group = create("stack-query", ResourceQuery=stack_query)
            if stack_group:
                rg("list_group_resources", "stack-members", Group=stack_group)
                rg("list_group_resources", "stack-members-type-exclusion", Group=stack_group,
                   Filters=[{"Name": "resource-type", "Values": ["AWS::S3::Bucket"]}])
            name_query = {"Type": "CLOUDFORMATION_STACK_1_0", "Query": json.dumps({
                "ResourceTypeFilters": ["AWS::AllSupported"], "StackIdentifier": name + "-stack"})}
            rg("search_resources", "stack-name-identifier", ResourceQuery=name_query)
        else:
            fixture["unavailable_dependencies"].append("Tiny CloudFormation stack failed: " + row["code"])
    finally:
        cleanup_phase = True
        for task in tasks:
            rg("cancel_tag_sync_task", "cleanup-task", TaskArn=task)
        if stack:
            call("cloudformation", "delete_stack", "cleanup-stack", StackName=stack)
            for attempt in range(60):
                row = call("cloudformation", "describe_stacks", "cleanup-stack-state-" + str(attempt), StackName=stack)
                if row["code"] != "Success" or row["output"]["Stacks"][0]["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
                    break
                time.sleep(5)
            call("sqs", "get_queue_url", "absence-stack-queue", QueueName=name + "-stack-queue")
            for group in groups:
                if group.endswith("-stack-query"):
                    rg("list_group_resources", "stack-group-after-stack-delete", Group=group)
        for group in reversed(groups):
            rg("delete_group", "cleanup-group", Group=group)
            rg("get_group", "absence-group", Group=group)
        for queue_name, url in queues:
            call("sqs", "delete_queue", "cleanup-queue", QueueUrl=url)
            call("sqs", "get_queue_url", "absence-queue", QueueName=queue_name)
        for bucket in buckets:
            call("s3", "delete_bucket", "cleanup-bucket", Bucket=bucket)
            call("s3", "head_bucket", "absence-bucket", Bucket=bucket)
        rg("get_account_settings", "account-settings-after-read-only")
        absence = [row for row in fixture["cleanup"] if row["case"].startswith("absence-")]
        expected_codes = {"absence-group": {"NotFoundException"},
                          "absence-queue": {"AWS.SimpleQueueService.NonExistentQueue"},
                          "absence-stack-queue": {"AWS.SimpleQueueService.NonExistentQueue"},
                          "absence-bucket": {"404", "NoSuchBucket"}}
        fixture["cleanup_verified"] = all(row["code"] in expected_codes[row["case"]] for row in absence)
        if stack:
            states = [row for row in fixture["cleanup"] if row["case"].startswith("cleanup-stack-state-")]
            fixture["cleanup_verified"] = fixture["cleanup_verified"] and bool(states) and (
                states[-1]["output"].get("Stacks", [{}])[0].get("StackStatus") == "DELETE_COMPLETE")
        save()
        print(json.dumps({"fixture": str(args.output), "observations": len(fixture["observations"]),
                          "cleanup_verified": fixture["cleanup_verified"],
                          "selection_matches": all(row["matches"] for row in fixture["selection"]) if fixture["selection"] else None}))
        if not fixture["cleanup_verified"]:
            raise RuntimeError("Exact-owned cleanup could not be verified; see retained fixture")


if __name__ == "__main__":
    main()
