#!/usr/bin/env python3
"""Consumer-visible Glue fixture assertions; never makes AWS calls.

Example: PYTHONPATH=scripts/aws python3 -P scripts/aws/glue_fixture_consumer.py \
  --kind catalog --reference testdata/aws/glue/catalog_verified.json \
  --actual /tmp/stackd-catalog-capture.json

The actual capture is produced by the corresponding probe with --endpoint-url.
Only meaningful state/error/pagination/partial-result contracts are compared, not
request IDs, clock values, error wording or backend-specific ARN spellings.
"""
import argparse
import json
from pathlib import Path


def load(path):
    capture = json.loads(Path(path).read_text())
    if not capture.get("completed") or not capture.get("cleanup", {}).get("verified"):
        raise AssertionError(str(path) + ": capture incomplete or cleanup not verified")
    return capture


def observations(capture):
    return {row["label"]: row["result"] for row in capture["observations"]}


def output(rows, label):
    result = rows[label]
    if result["code"] != "Success":
        raise AssertionError(label + ": " + result["code"])
    return result["output"]


def codes(rows, labels):
    return {label: rows[label]["code"] for label in labels}


def batch_errors(value, identity):
    return sorted((tuple(item[identity]) if isinstance(item[identity], list) else item[identity],
                   item["ErrorDetail"]["ErrorCode"]) for item in value["Errors"])


def catalog_contract(capture):
    rows = observations(capture)
    versions = {}
    for label in ("versions-initial", "versions-after-archive", "versions-after-skip"):
        versions[label] = sorted((item["VersionId"], item["Table"]["Description"], item["Table"].get("Parameters"))
                                 for item in output(rows, label)["TableVersions"])
    batches = {}
    for label, identity in (("batch-create-partial", "PartitionValues"), ("batch-update-partial", "PartitionValueList"), ("batch-delete-partial", "PartitionValues"), ("batch-delete-tables-partial", "TableName")):
        batches[label] = batch_errors(output(rows, label), identity)
    pages = [output(rows, "tables-page-one"), output(rows, "tables-page-two")]
    partitions = lambda label: sorted(item["Values"] for item in output(rows, label)["Partitions"])
    value = {
        "codes": codes(rows, ("duplicate-database", "get-database-uppercase", "get-database-other-catalog", "duplicate-table", "get-table-uppercase", "get-version-one-after-skip", "get-version-missing", "batch-create-invalid-arity", "get-deleted-partition", "get-retained-partition", "get-deleted-table", "delete-version-2", "get-table-after-delete", "get-partition-after-table-delete", "delete-database-again", "get-tables-after-database-delete")),
        "versions": versions, "partial_errors": batches,
        "partitions_after_invalid_batch": partitions("get-partitions-after-invalid-arity"),
        "partitions_after_partial_batch": partitions("get-partitions-after-partial"),
        "filtered_partitions": partitions("get-partitions-expression"),
        "batch_get_found": partitions("batch-get-partial"),
        "batch_get_unprocessed": output(rows, "batch-get-partial").get("UnprocessedKeys"),
        "updated_partition_parameters": output(rows, "get-updated-partition")["Partition"].get("Parameters"),
        "table_page_names": [[table["Name"] for table in page["TableList"]] for page in pages],
        "table_page_continuation": ["NextToken" in page for page in pages],
        "recreated_database_tables": output(rows, "recreated-database-tables")["TableList"],
    }
    assert value["partitions_after_invalid_batch"] == [["2026-01-01"]], "Invalid arity batch must not partially create valid entries"
    assert value["partitions_after_partial_batch"] == [["2026-01-01"], ["2026-01-02"]]
    assert value["updated_partition_parameters"] == {"updated": "yes"}
    assert value["recreated_database_tables"] == []
    return value


def registry_contract(capture):
    rows = observations(capture)
    first = output(rows, "get-avro-version-one")["SchemaVersionId"]
    duplicate_labels = ("register-avro-exact-duplicate", "register-avro-whitespace-duplicate", "lookup-avro-whitespace")
    def metadata(label):
        values = output(rows, label)["MetadataInfoMap"]
        return {key: {"primary": item["MetadataValue"], "other": sorted(other["MetadataValue"] for other in item.get("OtherMetadataValueList", []))} for key, item in values.items()}
    value = {
        "codes": codes(rows, ("duplicate-registry", "create-schema-omitted-compatibility-AVRO", "create-schema-omitted-compatibility-JSON", "create-schema-omitted-compatibility-PROTOBUF", "create-schema-without-definition", "duplicate-schema", "put-metadata-duplicate", "remove-metadata-missing-value", "update-compatibility-without-checkpoint", "delete-version-one", "schema-other-registry")),
        "validity": {fmt: (output(rows, "validate-" + fmt)["Valid"], output(rows, "validate-invalid-" + fmt)["Valid"]) for fmt in ("AVRO", "JSON", "PROTOBUF")},
        "duplicate_version_identity": {label: output(rows, label)["SchemaVersionId"] == first for label in duplicate_labels},
        "version_states": {label: {key: output(rows, label)[key] for key in ("VersionNumber", "Status")} for label in ("register-avro-compatible", "register-avro-incompatible", "incompatible-version-0")},
        "retained_versions": sorted((item["VersionNumber"], item["Status"]) for item in output(rows, "versions-after-evolution")["Schemas"]),
        "metadata": metadata("get-metadata"), "metadata_after_remove": metadata("get-metadata-after-remove"),
        "delete_missing": [(item["VersionNumber"], item["ErrorDetails"]["ErrorCode"]) for item in output(rows, "delete-version-missing")["SchemaVersionErrors"]],
        "json_reordered_version": output(rows, "register-json-reordered")["VersionNumber"],
    }
    assert all(value["duplicate_version_identity"].values())
    assert value["version_states"]["incompatible-version-0"] == {"VersionNumber": 3, "Status": "FAILURE"}
    assert value["metadata_after_remove"] == {"owner": {"primary": "two", "other": []}}
    return value


def registry_boundaries_contract(capture):
    rows = observations(capture)
    value = {}
    for mode in ("BACKWARD_ALL", "FULL_ALL"):
        first = output(rows, mode + "-incompatible")
        repeated = output(rows, mode + "-incompatible-duplicate")
        latest = output(rows, mode + "-latest-after-failure")
        value[mode] = {
            "failed_duplicate_same_id": first["SchemaVersionId"] == repeated["SchemaVersionId"],
            "failed_duplicate_state": repeated["Status"],
            "failed_duplicate_number": repeated["VersionNumber"],
            "latest_number": latest["VersionNumber"], "latest_state": latest["Status"],
            "delete_noncheckpoint_errors": output(rows, mode + "-delete-version-two")["SchemaVersionErrors"],
        }
        assert value[mode]["failed_duplicate_same_id"]
        assert latest["VersionNumber"] == 2 and latest["Status"] == "AVAILABLE"
        assert repeated["VersionNumber"] == 3 and repeated["Status"] == "FAILURE"
    return value


def controls_contract(capture):
    rows = observations(capture)
    def prune_time(value):
        return {key: item for key, item in value.items() if key not in ("CreationTime", "LastUpdated", "CreatedOn", "LastModifiedOn", "LastUpdatedTime", "LastUpdatedBy")}
    connections = {label: output(rows, label)["Connection"]["ConnectionProperties"] for label in ("get-connection-default", "get-connection-visible", "get-connection-hidden")}
    value = {
        "codes": codes(rows, ("duplicate-Csv-classifier", "duplicate-Json-classifier", "duplicate-connection", "get-connection-other-catalog", "create-crawler-invalid-targets", "duplicate-crawler", "stop-ready-crawler", "duplicate-workflow", "get-missing-workflow-run-properties", "create-on-demand-start-on-creation", "start-trigger-missing-job", "stop-on-demand-trigger", "duplicate-security", "create-security-missing-kms-key", "get-tags-malformed-arn", "get-tags-missing-resource", "get-tags-other-region", "create-job-exact-duplicate", "create-job-changed-description", "create-job-changed-script")),
        "connection_properties": connections,
        "updated_classifiers": {kind: prune_time(output(rows, "get-updated-" + kind + "-classifier")["Classifier"][kind + "Classifier"]) for kind in ("Csv", "Json")},
        "crawler_states": [output(rows, label)["Crawler"]["State"] for label in ("get-crawler", "get-updated-crawler")],
        "workflow_properties": [output(rows, label)["Workflow"].get("DefaultRunProperties") for label in ("get-workflow", "get-updated-workflow")],
        "trigger_states": [output(rows, label)["Trigger"]["State"] for label in ("get-trigger", "get-trigger-after-start", "get-trigger-after-stop")],
        "tag_merge": output(rows, "get-merged-workflow-tags"), "tag_removal": output(rows, "get-remaining-workflow-tags"),
        "job_after_duplicate_description": output(rows, "get-job-after-duplicate")["Job"].get("Description"),
        "job_after_replacement": {key: output(rows, "get-job-after-replacement")["Job"].get(key) for key in ("Description", "DefaultArguments", "MaxCapacity", "Timeout")},
    }
    assert "PASSWORD" in connections["get-connection-default"] and "PASSWORD" not in connections["get-connection-hidden"]
    return value


CONTRACTS = {"catalog": catalog_contract, "registry": registry_contract,
             "registry-boundaries": registry_boundaries_contract, "controls": controls_contract}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=CONTRACTS, required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--actual")
    args = parser.parse_args()
    expected = CONTRACTS[args.kind](load(args.reference))
    if args.actual:
        actual = CONTRACTS[args.kind](load(args.actual))
        if actual != expected:
            raise AssertionError(json.dumps({"expected": expected, "actual": actual}, indent=2))
        print(args.kind + ": native fixture comparison passed")
    else:
        print(json.dumps(expected, indent=2))
        print(args.kind + ": native consumer invariants passed (local replay not exercised)")


if __name__ == "__main__":
    main()
