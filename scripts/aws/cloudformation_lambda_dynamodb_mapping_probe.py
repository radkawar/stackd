#!/usr/bin/env python3
"""Capture native CFN DynamoDB stream mapping defaults, removal and replacement.

All mappings remain disabled; no records or invocations are sent. Evidence is
never overwritten. --cleanup-only resumes the exact-owned durable inventory.
The Kinesis/Layer/Version helpers supply recording, bounded waits, stack handling
and common exact-owned cleanup; only the source lifecycle differs here.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import time
import uuid

import boto3
import botocore
from botocore.config import Config

from cloudformation_lambda_kinesis_mapping_probe import KinesisMappingProbe, SOURCES
from cloudtrail_service_probe import REGION, document, now


class DynamoDBMappingProbe(KinesisMappingProbe):
    def __init__(self, args):
        self.args = args
        self.account = args.account
        self.actor = "arn:aws:iam::" + self.account + ":user/Delegated"
        self.session = boto3.Session(region_name=REGION)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        self.clients = {name: self.session.client(name, config=config) for name in
                        ("sts", "iam", "lambda", "cloudformation", "logs", "dynamodb")}
        self.credentials = self.session.get_credentials().get_frozen_credentials()
        self.cleanup_phase = False
        if args.cleanup_only:
            self.data = json.loads(args.output.read_text())
            if (self.data["account"], self.data["region"]) != (self.account, REGION):
                raise RuntimeError("Inventory outside approved account/region")
            if not self.data["prefix"].startswith("stackd-cfn-dynamodb-"):
                raise RuntimeError("Not a CFN DynamoDB mapping inventory")
        else:
            if args.output.exists():
                raise RuntimeError("Refusing to overwrite native evidence")
            self.data = {
                "source": "Native AWS public endpoints; signed boto3; endpoint overrides disabled",
                "captured_at": now(), "account": self.account, "region": REGION,
                "prefix": "stackd-cfn-dynamodb-" + uuid.uuid4().hex[:12],
                "sdk": {"boto3": boto3.__version__, "botocore": botocore.__version__,
                        "models": {name: {"api_version": client.meta.service_model.api_version,
                                           "endpoint": client.meta.endpoint_url}
                                   for name, client in self.clients.items()}},
                "environment": {"credential_method": self.session.get_credentials().method,
                                "aws_variable_names": sorted(k for k in os.environ if k.startswith("AWS_"))},
                "scope": "At most two exact-owned PAY_PER_REQUEST tables with streams, one disabled mapping stack, one non-invoked function with version/aliases, exact-source/log-scoped role and owned log group; no public grants",
                "mode": "dynamodb-lifecycle",
                "bounds": {"stack_wait_seconds": 420, "resource_wait_seconds": 180, "poll_seconds": 3},
                "owned": {"stacks": {}, "streams": {}, "tables": {}, "mappings": []},
                "calls": [], "findings": {}, "templates": {},
                "sources": SOURCES[:-1] + ["https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html"],
                "calibration_gaps": [
                    "Control-plane deployment only; no DynamoDB records or Lambda invocations are sent.",
                    "Private CloudFormation ownership tokens, restart recovery and local native-engine equivalence are not measured.",
                    "Encrypted filters/KmsKeyArn and failure destinations are not provisioned or calibrated.",
                    "No KMS keys, public grants, provisioned capacity or cross-account sources are created.",
                ],
                "cleanup": {"complete": False}, "workflow_complete": False,
            }
        self.save()
        identity = self.call("identity-before-writes", "sts", "get_caller_identity")
        self.data["identity"] = identity
        self.save()
        if identity["Account"] != self.account or identity["Arn"] != self.actor:
            raise RuntimeError("Native writes require the approved account and IAM user Delegated")

    def setup_stream(self, key):
        tables = self.data["owned"]["tables"]
        if key not in ("first", "second") or key in tables or len(tables) >= 2:
            raise RuntimeError("Refusing more than two exact-owned table incarnations")
        name = self.data["prefix"] + "-" + key
        arn = "arn:aws:dynamodb:" + REGION + ":" + self.account + ":table/" + name
        self.absent(key + "-table-name-absent", "dynamodb", "describe_table",
                    {"TableName": name}, "ResourceNotFoundException")
        owned = {"name": name, "arn": arn, "absence_verified": True, "creation_attempted": True}
        tables[key] = owned
        self.save()
        created = self.call(key + "-create-table", "dynamodb", "create_table", {
            "TableName": name, "BillingMode": "PAY_PER_REQUEST",
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "StreamSpecification": {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
            "Tags": [{"Key": "stackd-probe", "Value": self.data["prefix"]}]})["TableDescription"]
        owned.update(creation_confirmed=True, id=created["TableId"],
                     created_at=document(created["CreationDateTime"]), stream_arn=created.get("LatestStreamArn"))
        self.save()
        ready = self.wait_resource(key + "-table-ready", "dynamodb", "describe_table", {"TableName": name},
            lambda value, code: value.get("Table", {}).get("TableStatus") == "ACTIVE"
            and bool(value.get("Table", {}).get("LatestStreamArn")))["Table"]
        owned["stream_arn"] = ready["LatestStreamArn"]
        self.save()
        return owned["stream_arn"]

    def source_arns(self):
        return [table["stream_arn"] for table in self.data["owned"]["tables"].values() if table.get("stream_arn")]

    def source_policy(self):
        owned = self.data["owned"]
        statements = [
            {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": owned["log_group"]["arn"] + ":*"},
            {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                                         "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
             "Resource": self.source_arns()},
        ]
        owned["role"]["policy"] = "owned-source-and-logs"
        self.save()
        request = {"RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"]}
        self.call("put-owned-source-and-log-policy", "iam", "put_role_policy",
                  {**request, "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
        self.call("read-owned-source-and-log-policy", "iam", "get_role_policy", request)
        time.sleep(15)

    def authority_workflow(self):
        self.data["mode"] = "dynamodb-liststreams-admission"
        self.save()
        source = self.setup()
        owned = self.data["owned"]
        request = {"RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"]}
        for label, listing in (
                ("without-liststreams", None),
                ("stream-scoped-liststreams", {"Effect": "Allow", "Action": "dynamodb:ListStreams", "Resource": source}),
                ("deny-liststreams", {"Effect": "Deny", "Action": "dynamodb:ListStreams", "Resource": "*"})):
            statements = [
                {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": owned["log_group"]["arn"] + ":*"},
                {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                                             "dynamodb:GetShardIterator"], "Resource": source},
            ]
            if listing is not None:
                statements.append(listing)
            policy = {"Version": "2012-10-17", "Statement": statements}
            self.call(label + "-put-policy", "iam", "put_role_policy",
                      {**request, "PolicyDocument": json.dumps(policy)})
            self.call(label + "-read-policy", "iam", "get_role_policy", request)
            time.sleep(30)
            created = self.call(label + "-create-disabled-mapping", "lambda", "create_event_source_mapping", {
                "EventSourceArn": source, "FunctionName": owned["function"]["arn"],
                "StartingPosition": "LATEST", "Enabled": False}, required=False)
            result = {"policy": policy, "policy_propagation_wait_seconds": 30,
                      "create_code": self.code(), "create_response": created}
            if created:
                identifier = created["UUID"]
                owned["mappings"].append(identifier)
                self.save()
                result["ready_mapping"] = self.wait_resource(label + "-mapping-ready", "lambda", "get_event_source_mapping",
                    {"UUID": identifier}, lambda value, code: value.get("State") == "Disabled")
                self.call(label + "-delete-mapping", "lambda", "delete_event_source_mapping", {"UUID": identifier})
                self.wait_resource(label + "-mapping-absent", "lambda", "get_event_source_mapping",
                    {"UUID": identifier}, lambda value, code: code == "ResourceNotFoundException")
            else:
                result["create_error"] = self.data["calls"][-1].get("error")
            self.finding(label, result)
        self.data["workflow_complete"] = True
        self.save()

    def workflow(self):
        self.documents()
        first = self.setup()
        base = {"EventSourceArn": first, "FunctionName": self.data["owned"]["function"]["arn"],
                "StartingPosition": "LATEST", "Enabled": False}
        fresh = self.require_complete(self.stack("fresh-defaults", base))
        settings = {"BatchSize": 17, "MaximumBatchingWindowInSeconds": 2, "ParallelizationFactor": 2,
                    "MaximumRetryAttempts": 2, "MaximumRecordAgeInSeconds": 120,
                    "BisectBatchOnFunctionError": True,
                    "FilterCriteria": {"Filters": [{"Pattern": json.dumps({"dynamodb": {
                        "NewImage": {"pk": {"S": [self.data["prefix"]]}}}})}]},
                    "MetricsConfig": {"Metrics": ["EventCount"]},
                    "FunctionResponseTypes": ["ReportBatchItemFailures"],
                    "Tags": [{"Key": "owned-setting", "Value": self.data["prefix"]}]}
        configured_result = self.stack("explicit-settings", {**base, **settings}, update=True)
        configured = self.require_complete(configured_result)
        removed_result = self.stack("remove-settings", base, update=True)
        removed = self.require_complete(removed_result)
        self.finding("property-removal", {"same_uuid": fresh["UUID"] == configured["UUID"] == removed["UUID"],
            "properties": {key: {"fresh": fresh.get(key), "explicit": configured.get(key), "removed": removed.get(key),
                                   "after_equals_fresh": removed.get(key) == fresh.get(key),
                                   "after_equals_explicit": removed.get(key) == configured.get(key)}
                           for key in settings if key != "Tags"},
            "explicit_tags": configured_result.get("tags"), "removed_tags": removed_result.get("tags")})
        tumbling = self.require_complete(self.stack("explicit-tumbling",
            {**base, "ParallelizationFactor": 1, "TumblingWindowInSeconds": 5}, update=True))
        removed_tumbling = self.require_complete(self.stack("remove-tumbling", base, update=True))
        self.finding("tumbling-removal", {"fresh": fresh.get("TumblingWindowInSeconds"),
            "explicit": tumbling.get("TumblingWindowInSeconds"), "removed": removed_tumbling.get("TumblingWindowInSeconds"),
            "same_uuid": tumbling["UUID"] == removed_tumbling["UUID"]})
        function = self.data["owned"]["function"]
        version = self.call("publish-retarget-version", "lambda", "publish_version",
                            {"FunctionName": function["arn"]})["Version"]
        function["versions"].append(version)
        function["aliases"] = []
        self.save()
        for alias in ("first", "second"):
            function["aliases"].append(alias)
            self.save()
            self.call("create-retarget-alias-" + alias, "lambda", "create_alias",
                      {"FunctionName": function["arn"], "Name": alias, "FunctionVersion": version})
        first_target = self.require_complete(self.stack("retarget-first-alias",
            {**base, "FunctionName": function["arn"] + ":first"}, update=True))
        second_target = self.require_complete(self.stack("retarget-second-alias",
            {**base, "FunctionName": function["arn"] + ":second"}, update=True))
        self.finding("function-retarget", {"same_uuid": fresh["UUID"] == first_target["UUID"] == second_target["UUID"],
            "base_function": fresh["FunctionArn"], "first_alias": first_target["FunctionArn"],
            "second_alias": second_target["FunctionArn"], "invocation_exercised": False})
        base["FunctionName"] = function["arn"] + ":second"
        position = self.stack("replace-starting-position", {**base, "StartingPosition": "TRIM_HORIZON"}, update=True)
        if position.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("StartingPosition replacement did not settle")
        if position["stack_status"] == "UPDATE_COMPLETE":
            base["StartingPosition"] = "TRIM_HORIZON"
        second = self.setup_stream("second")
        self.source_policy()
        second_properties = {**base, "EventSourceArn": second}
        invalid_timestamp = self.stack("reject-dynamodb-at-timestamp", {**second_properties,
            "StartingPosition": "AT_TIMESTAMP", "StartingPositionTimestamp": int(time.time()) - 60}, update=True)
        if invalid_timestamp.get("stack_status") not in ("UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"):
            raise RuntimeError("Unsupported timestamp scenario did not settle")
        replacement = self.require_complete(self.stack("replace-source-arn", second_properties, update=True))
        old_uuid = position["mapping"]["UUID"]
        old_mapping = self.call("source-replacement-old-mapping", "lambda", "get_event_source_mapping",
                                {"UUID": old_uuid}, required=False)
        self.finding("source-replacement", {"old_uuid": old_uuid, "new_uuid": replacement["UUID"],
            "old_source": first, "new_source": second, "old_mapping": old_mapping, "old_mapping_code": self.code()})
        status = self.delete_stack("mapping", "explicit-delete-stack")
        self.absent("explicit-delete-mapping-absent", "lambda", "get_event_source_mapping",
                    {"UUID": replacement["UUID"]}, "ResourceNotFoundException")
        tables = {key: self.call("after-mapping-delete-table-" + key, "dynamodb", "describe_table",
                                {"TableName": table["name"]})["Table"]["TableStatus"]
                  for key, table in self.data["owned"]["tables"].items()}
        current_function = self.call("after-mapping-delete-function", "lambda", "get_function_configuration",
                                     {"FunctionName": function["arn"]})
        self.finding("mapping-deletion", {"stack_status": status, "mapping_absent": True,
            "table_statuses": tables, "function_state": current_function["State"]})
        self.data["workflow_complete"] = True
        self.save()

    def cleanup(self, source_cleanup=None):
        def remove_table(key, table):
            request = {"TableName": table["name"]}
            current = self.call("cleanup-table-identity-" + key, "dynamodb", "describe_table", request, required=False)
            if not current and self.code() == "ResourceNotFoundException":
                return
            value = current["Table"]
            if (value["TableArn"] != table["arn"] or
                    (table.get("id") and value["TableId"] != table["id"]) or
                    (table.get("created_at") and document(value["CreationDateTime"]) != table["created_at"])):
                raise RuntimeError("Table identity changed: " + table["arn"])
            if value["TableStatus"] != "DELETING":
                tags = self.call("cleanup-table-tags-" + key, "dynamodb", "list_tags_of_resource",
                                 {"ResourceArn": table["arn"]})
                if {item["Key"]: item["Value"] for item in tags.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
                    raise RuntimeError("Table ownership tag changed: " + table["arn"])
                self.call("cleanup-delete-table-" + key, "dynamodb", "delete_table", request)
            self.wait_resource("cleanup-table-absent-" + key, "dynamodb", "describe_table", request,
                               lambda value, code: code == "ResourceNotFoundException")

        def remove_tables(attempt):
            for key, table in self.data["owned"]["tables"].items():
                attempt("table " + key, lambda key=key, table=table: remove_table(key, table))
            if source_cleanup is not None:
                source_cleanup(attempt)

        try:
            super().cleanup(source_cleanup=remove_tables)
        finally:
            self.data["cleanup"]["boundary"] = (
                "Exact-owned table/function/mapping/log/role IDs verified absent when complete; "
                "deleted stack ARN retains DELETE_COMPLETE history; DynamoDB deleted-stream retention is service managed")
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_dynamodb_mapping.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--authority-only", action="store_true",
                        help="Calibrate disabled direct Lambda admission with three bounded ListStreams IAM policies")
    args = parser.parse_args()
    args.schema_output = None
    args.sqs_only = False
    probe = DynamoDBMappingProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            if args.authority_only:
                probe.authority_workflow()
            else:
                probe.workflow()
    except Exception as error:
        probe.data["failure"] = {"at": now(), "error": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
