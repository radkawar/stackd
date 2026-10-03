#!/usr/bin/env python3
"""Capture native CFN encrypted-filter and failure-destination control semantics.

One disabled DynamoDB stream mapping, one non-invoked function, one on-demand
source table, one destination queue and one symmetric KMS key are exact-owned.
No records or invocations are sent. Evidence is never overwritten. Resume only
cleanup with --cleanup-only; KMS cleanup means verified PendingDeletion, not
immediate absence. Existing filter_kms_native.json supplies direct Lambda KMS
contrast; this capture measures CloudFormation omission and empty properties.
"""
import argparse
import copy
import json
from pathlib import Path
import signal
import time

from botocore.config import Config

from cloudformation_lambda_dynamodb_mapping_probe import DynamoDBMappingProbe
from cloudtrail_service_probe import REGION, document, now

SOURCES = [
    "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filter-criteria-encryption",
    "https://docs.aws.amazon.com/lambda/latest/api/API_UpdateEventSourceMapping.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html",
    "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-onfailure.html",
    "https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html",
    "https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html",
]


class MappingControlsProbe(DynamoDBMappingProbe):
    def __init__(self, args):
        if args.cleanup_only:
            inventory = json.loads(args.output.read_text())
            if inventory.get("mode") != "dynamodb-mapping-controls":
                raise RuntimeError("Not a mapping-controls inventory")
        super().__init__(args)
        config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                        retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=35)
        for service in ("sqs", "kms"):
            client = self.session.client(service, config=config)
            self.clients[service] = client
            self.data["sdk"]["models"][service] = {
                "api_version": client.meta.service_model.api_version, "endpoint": client.meta.endpoint_url}
        if not args.cleanup_only:
            self.data.update(
                mode="dynamodb-mapping-controls",
                scope="One exact-owned PAY_PER_REQUEST table/stream, one disabled CFN mapping stack, one non-invoked function, source/log/destination-scoped role, one owned log group, one SQS failure destination and one symmetric KMS key; no public grants",
                sources=SOURCES,
                primary_evidence=["testdata/aws/lambda/filter_kms_native.json"],
                calibration_gaps=[
                    "Control-plane deployment only; no DynamoDB records, destination messages or Lambda invocations are sent.",
                    "No SQS source contrast: existing direct Lambda SQS filter_kms_native.json remains separate evidence, not CFN removal evidence.",
                    "One KMS key suffices to compare add/remove/re-add UUID identity; switching between two distinct customer keys is not measured.",
                    "Private CloudFormation handler requests are not inferred from final native state; actual templates, failures, rollback events and Get/List responses are retained.",
                    "Scheduled KMS deletion is verified as PendingDeletion with its deletion date; the key is not immediately absent.",
                ],
                transitions=[],
            )
        self.save()
        self.current_properties = None
        self.current_mapping = None

    def setup_stream(self, key):
        if key != "first" or self.data["owned"]["tables"]:
            raise RuntimeError("Controls calibration admits only one owned table")
        return super().setup_stream(key)

    def source_policy(self):
        owned = self.data["owned"]
        statements = [
            {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": owned["log_group"]["arn"] + ":*"},
            {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                                         "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
             "Resource": self.source_arns()},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": owned["queue"]["arn"]},
        ]
        owned["role"]["policy"] = "owned-source-logs-and-destination"
        self.save()
        request = {"RoleName": owned["role"]["name"], "PolicyName": owned["role"]["policy"]}
        self.call("put-owned-source-log-destination-policy", "iam", "put_role_policy",
                  {**request, "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
        self.call("read-owned-source-log-destination-policy", "iam", "get_role_policy", request)
        time.sleep(15)

    def setup_key(self, mapping):
        if "key" in self.data["owned"]:
            raise RuntimeError("Controls calibration admits only one owned KMS key")
        policy = {"Version": "2012-10-17", "Statement": [
            {"Sid": "OwnedProbeAdministrator", "Effect": "Allow",
             "Principal": {"AWS": "arn:aws:iam::" + self.account + ":root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "ExactOwnedMappingDecrypt", "Effect": "Allow",
             "Principal": {"Service": "lambda." + REGION + ".amazonaws.com"},
             "Action": "kms:Decrypt", "Resource": "*", "Condition": {
                 "ArnEquals": {"aws:SourceArn": mapping["EventSourceMappingArn"]},
                 "StringEquals": {
                     "kms:EncryptionContext:aws:lambda:FunctionArn": mapping["FunctionArn"],
                     "kms:EncryptionContext:aws:lambda:EventSourceArn": mapping["EventSourceArn"]}}},
        ]}
        key = {"description": self.data["prefix"] + "-filter-key", "creation_attempted": True}
        self.data["owned"]["key"] = key
        self.save()
        created = self.call("create-owned-filter-key", "kms", "create_key", {
            "Description": key["description"], "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS", "MultiRegion": False,
            "Policy": json.dumps(policy),
            "Tags": [{"TagKey": "stackd-probe", "TagValue": self.data["prefix"]}]})["KeyMetadata"]
        key.update(id=created["KeyId"], arn=created["Arn"], created_at=document(created["CreationDate"]),
                   creation_confirmed=True)
        self.save()
        self.wait_resource("owned-key-enabled", "kms", "describe_key", {"KeyId": key["arn"]},
                           lambda value, code: value.get("KeyMetadata", {}).get("KeyState") == "Enabled")
        self.call("read-owned-filter-key-policy", "kms", "get_key_policy",
                  {"KeyId": key["arn"], "PolicyName": "default"})
        return key["arn"]

    @staticmethod
    def controls(mapping):
        return {name: {"present": name in mapping, "value": mapping.get(name)} for name in
                ("UUID", "KMSKeyArn", "FilterCriteria", "FilterCriteriaError", "DestinationConfig", "State")}

    def scenario(self, label, properties, *, required=False):
        before = self.current_mapping
        result = self.stack(label, properties, update=self.current_properties is not None)
        status = result.get("stack_status")
        if status not in ("CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", None):
            raise RuntimeError(label + ": unsettled native stack " + str(status))
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            self.current_properties = copy.deepcopy(properties)
        if "mapping" not in result and before:
            result["mapping"] = self.call(label + "-after-rejection-mapping", "lambda", "get_event_source_mapping",
                                          {"UUID": before["UUID"]})
        mapping = result.get("mapping", {})
        if mapping:
            self.current_mapping = mapping
            result["list"] = self.call(label + "-list-mappings", "lambda", "list_event_source_mappings", {
                "FunctionName": mapping["FunctionArn"], "EventSourceArn": mapping["EventSourceArn"]})
        transition = {"label": label, "submission_code": result["submission_code"], "stack_status": status,
                      "requested_properties": copy.deepcopy(properties),
                      "before": self.controls(before or {}), "after": self.controls(mapping),
                      "same_uuid": before["UUID"] == mapping.get("UUID") if before else None}
        self.data["transitions"].append(transition)
        self.save()
        print("CONTROL " + json.dumps(document(transition)), flush=True)
        if required:
            self.require_complete(result)
        return result

    def restore(self, label, properties):
        if properties != self.current_properties:
            self.scenario(label, properties, required=True)

    def workflow(self):
        self.documents()
        destination = self.setup_queue()
        source = self.setup()
        base = {"EventSourceArn": source, "FunctionName": self.data["owned"]["function"]["arn"],
                "StartingPosition": "LATEST", "Enabled": False}
        fresh = self.scenario("fresh-defaults", base, required=True)["mapping"]
        key = self.setup_key(fresh)
        filters = {"Filters": [{"Pattern": json.dumps({"dynamodb": {
            "NewImage": {"pk": {"S": [self.data["prefix"]]}}}})}]}
        configured = {**base, "FilterCriteria": filters, "KmsKeyArn": key,
                      "DestinationConfig": {"OnFailure": {"Destination": destination}}}
        self.scenario("encrypted-filter-and-destination", configured, required=True)
        self.scenario("omit-key-keep-filter", {name: value for name, value in configured.items() if name != "KmsKeyArn"})
        self.restore("restore-key-after-omission", configured)
        self.scenario("omit-filter-keep-key", {name: value for name, value in configured.items() if name != "FilterCriteria"})
        self.restore("restore-filter-after-omission", configured)
        self.scenario("empty-filter-keep-key", {**configured, "FilterCriteria": {}})
        self.restore("restore-filter-after-empty", configured)
        self.scenario("empty-key-keep-filter", {**configured, "KmsKeyArn": ""})
        self.restore("restore-key-after-empty", configured)
        without_destination = {name: value for name, value in configured.items() if name != "DestinationConfig"}
        self.scenario("omit-destination", without_destination)
        self.restore("restore-destination-after-omission", configured)
        for label, value in (("empty-destination-config", {}),
                             ("empty-onfailure", {"OnFailure": {}}),
                             ("empty-destination-string", {"OnFailure": {"Destination": ""}})):
            self.scenario(label, {**configured, "DestinationConfig": value})
            self.restore("restore-after-" + label, configured)
        self.finding("mapping-controls-summary", {
            "mapping_ids": sorted({item["after"]["UUID"]["value"] for item in self.data["transitions"]
                                   if item["after"]["UUID"]["present"]}),
            "all_updates_same_uuid": all(item["same_uuid"] for item in self.data["transitions"][1:]),
            "cfn_key_property": "KmsKeyArn", "lambda_key_field": "KMSKeyArn",
            "records_sent": 0, "invocations_sent": 0,
        })
        self.data["workflow_complete"] = True
        self.save()

    def cleanup_key(self):
        key = self.data["owned"].get("key")
        if not key:
            return
        if not key.get("arn"):
            for row in self.data["calls"]:
                if row["label"] == "create-owned-filter-key" and row.get("output", {}).get("KeyMetadata"):
                    metadata = row["output"]["KeyMetadata"]
                    key.update(id=metadata["KeyId"], arn=metadata["Arn"], created_at=metadata["CreationDate"])
                    self.save()
                    break
            else:
                creation = [row for row in self.data["calls"] if row["label"] == "create-owned-filter-key"]
                if creation and creation[-1]["code"] in ("AccessDeniedException", "MalformedPolicyDocumentException",
                                                        "InvalidArnException", "ValidationException"):
                    self.data["cleanup"]["key"] = {"creation_rejected": creation[-1]["code"]}
                    self.save()
                    return
                raise RuntimeError("KMS creation disposition unknown; no returned key identity; no blind create retry")
        for identifier in self.data["owned"]["mappings"]:
            self.absent("cleanup-before-key-mapping-absent-" + identifier, "lambda", "get_event_source_mapping",
                        {"UUID": identifier}, "ResourceNotFoundException")
        request = {"KeyId": key["arn"]}
        current = self.call("cleanup-key-identity", "kms", "describe_key", request, required=False)
        if not current and self.code() == "NotFoundException":
            self.data["cleanup"]["key"] = {"arn": key["arn"], "absent": True}
            self.save()
            return
        metadata = current["KeyMetadata"]
        if (metadata["Arn"] != key["arn"] or metadata["KeyId"] != key["id"] or
                metadata["AWSAccountId"] != self.account or metadata["Description"] != key["description"] or
                document(metadata["CreationDate"]) != key["created_at"]):
            raise RuntimeError("KMS identity changed; refusing key deletion")
        tags = self.call("cleanup-key-tags", "kms", "list_resource_tags", request)
        if {item["TagKey"]: item["TagValue"] for item in tags.get("Tags", [])}.get("stackd-probe") != self.data["prefix"]:
            raise RuntimeError("KMS ownership tag changed; refusing key deletion")
        if metadata["KeyState"] != "PendingDeletion":
            self.call("cleanup-schedule-key-deletion", "kms", "schedule_key_deletion",
                      {**request, "PendingWindowInDays": 7})
        pending = self.wait_resource("cleanup-key-pending-deletion", "kms", "describe_key", request,
            lambda value, code: value.get("KeyMetadata", {}).get("KeyState") == "PendingDeletion")["KeyMetadata"]
        self.data["cleanup"]["key"] = {
            "arn": key["arn"], "state": pending["KeyState"], "deletion_date": document(pending["DeletionDate"]),
            "pending_window_days": pending.get("PendingDeletionWindowInDays", 7), "absent": False}
        self.save()

    def cleanup(self):
        try:
            super().cleanup(source_cleanup=lambda attempt: attempt("filter KMS key", self.cleanup_key))
        finally:
            self.data["cleanup"]["boundary"] = (
                "Exact-owned stack/mapping/table/function/queue/log/role cleanup verified when complete; "
                "stack ARN retains DELETE_COMPLETE history and DynamoDB deleted-stream retention is service managed. "
                "KMS key remains PendingDeletion until the retained deletion date; it is not claimed absent.")
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cloudformation/lambda_mapping_controls.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    args = parser.parse_args()
    args.schema_output = None
    args.sqs_only = False
    probe = MappingControlsProbe(args)

    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        if not args.cleanup_only:
            probe.workflow()
    except Exception as error:
        probe.data["failure"] = {"at": now(), "error": str(error)}
        probe.save()
        raise
    finally:
        probe.cleanup()


if __name__ == "__main__":
    main()
