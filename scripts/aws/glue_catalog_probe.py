#!/usr/bin/env python3
"""Capture owned Glue catalog versions, partition partial batches, scope and deletion.

Run: PYTHONPATH=scripts/aws python3 -P scripts/aws/glue_catalog_probe.py --native --account ACCOUNT_ID --member-account MEMBER_ACCOUNT_ID --output .stackd/probes/glue/catalog.json
No S3 objects, jobs, crawlers or paid engine resources are created by this probe.
"""
import copy

from glue_native_common import Capture, arguments, descriptor, require

REFERENCES = [
    "https://docs.aws.amazon.com/glue/latest/webapi/API_CreateDatabase.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_UpdateTable.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_GetTableVersions.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_BatchCreatePartition.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_BatchGetPartition.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_BatchUpdatePartition.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_BatchDeletePartition.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_BatchDeleteTable.html",
    "https://docs.aws.amazon.com/glue/latest/webapi/API_DeleteDatabase.html",
    "https://aws.amazon.com/glue/pricing/",
]


def main():
    args = arguments(__doc__, member_account=True)
    cap = Capture(args, "stackd_glue_", REFERENCES, {
        "max_calls": 90, "wall_seconds": 600, "cli_timeout_seconds": 30,
        "max_databases": 1, "max_tables": 2, "max_versions": 5, "max_partitions": 4,
        "cost_usd_upper_estimate": 0.01,
        "cost_basis": "No compute. <=90 metadata calls at $1/million beyond free tier; <=12 short-lived metadata objects.",
    })
    db = cap.prefix
    sd = descriptor("s3://stackd-uncreated-catalog-location/data/")
    table = {"Name": "sales", "Description": "revision-0", "TableType": "EXTERNAL_TABLE",
             "Parameters": {"classification": "csv", "retained": "initial"}, "StorageDescriptor": sd,
             "PartitionKeys": [{"Name": "day", "Type": "string"}]}
    created = False
    def call(label, op, params):
        return cap.request(label, "glue", op, params)
    def part(value):
        return {"Values": [value], "StorageDescriptor": dict(sd, Location=sd["Location"] + "day=" + value + "/")}
    try:
        cap.identity()
        cap.capture["uncertainty"] = [
            "Single-account owned ordinary Hive catalog path; no Lake Formation grants/defaults changed.",
            "No global database lists: catalog mismatch and region mismatch read only the unique owned database name.",
            "Batch order is retained as observed, not asserted as a universal sort guarantee.",
            "IAM explicit denial and real job/S3 consumers are recorded in the separate Athena application capture.",
            "Crawlers, registries, workflows, federated catalogs, Iceberg and governed transactions are not exercised.",
        ]
        created = True
        require(call("create-database", "create-database", {"DatabaseInput": {"Name": db, "Description": "owned native catalog"}}))
        call("duplicate-database", "create-database", {"DatabaseInput": {"Name": db}})
        call("get-database", "get-database", {"Name": db})
        call("get-database-uppercase", "get-database", {"Name": db.upper()})
        call("get-database-explicit-catalog", "get-database", {"CatalogId": cap.account, "Name": db})
        call("get-database-other-catalog", "get-database", {"CatalogId": args.member_account, "Name": db})
        if args.native:
            cap.request("get-database-other-region", "glue", "get-database", {"Name": db}, options=["--region", "us-west-2"])
        require(call("create-table", "create-table", {"DatabaseName": db, "TableInput": table}))
        call("duplicate-table", "create-table", {"DatabaseName": db, "TableInput": table})
        call("get-table-initial", "get-table", {"DatabaseName": db, "Name": "sales"})
        call("get-table-uppercase", "get-table", {"DatabaseName": db, "Name": "SALES"})
        call("versions-initial", "get-table-versions", {"DatabaseName": db, "TableName": "sales"})
        changed = copy.deepcopy(table)
        changed["Description"] = "revision-1"
        changed["Parameters"] = {"replacement": "yes"}
        require(call("update-table-archive", "update-table", {"DatabaseName": db, "TableInput": changed}))
        call("versions-after-archive", "get-table-versions", {"DatabaseName": db, "TableName": "sales"})
        changed["Description"] = "revision-2"
        require(call("update-table-skip-archive", "update-table", {"DatabaseName": db, "TableInput": changed, "SkipArchive": True}))
        call("versions-after-skip", "get-table-versions", {"DatabaseName": db, "TableName": "sales"})
        call("get-table-current", "get-table", {"DatabaseName": db, "Name": "sales"})
        call("get-version-zero", "get-table-version", {"DatabaseName": db, "TableName": "sales", "VersionId": "0"})
        call("get-version-one-after-skip", "get-table-version", {"DatabaseName": db, "TableName": "sales", "VersionId": "1"})
        call("get-version-missing", "get-table-version", {"DatabaseName": db, "TableName": "sales", "VersionId": "999"})
        require(call("create-second-table", "create-table", {"DatabaseName": db, "TableInput": {"Name": "alpha"}}))
        first = require(call("tables-page-one", "get-tables", {"DatabaseName": db, "MaxResults": 1}))
        if first.get("NextToken"):
            cap.name(first["NextToken"], "TABLES_PAGE_TOKEN")
            call("tables-page-two", "get-tables", {"DatabaseName": db, "MaxResults": 1, "NextToken": first["NextToken"]})
        call("tables-filter", "get-tables", {"DatabaseName": db, "Expression": "sal.*"})
        require(call("create-partition", "create-partition", {"DatabaseName": db, "TableName": "sales", "PartitionInput": part("2026-01-01")}))
        call("batch-create-invalid-arity", "batch-create-partition", {"DatabaseName": db, "TableName": "sales", "PartitionInputList": [part("2026-01-01"), part("2026-01-02"), {"Values": ["bad", "extra"], "StorageDescriptor": sd}]})
        call("get-partitions-after-invalid-arity", "get-partitions", {"DatabaseName": db, "TableName": "sales"})
        call("batch-create-partial", "batch-create-partition", {"DatabaseName": db, "TableName": "sales", "PartitionInputList": [part("2026-01-01"), part("2026-01-02")]})
        call("get-partitions-after-partial", "get-partitions", {"DatabaseName": db, "TableName": "sales"})
        call("get-partitions-expression", "get-partitions", {"DatabaseName": db, "TableName": "sales", "Expression": "day >= '2026-01-02'"})
        call("batch-get-partial", "batch-get-partition", {"DatabaseName": db, "TableName": "sales", "PartitionsToGet": [{"Values": ["2026-01-02"]}, {"Values": ["missing"]}, {"Values": ["2026-01-01"]}]})
        call("batch-update-partial", "batch-update-partition", {"DatabaseName": db, "TableName": "sales", "Entries": [{"PartitionValueList": ["2026-01-02"], "PartitionInput": dict(part("2026-01-02"), Parameters={"updated": "yes"})}, {"PartitionValueList": ["missing"], "PartitionInput": part("missing")}]})
        call("get-updated-partition", "get-partition", {"DatabaseName": db, "TableName": "sales", "PartitionValues": ["2026-01-02"]})
        call("batch-delete-partial", "batch-delete-partition", {"DatabaseName": db, "TableName": "sales", "PartitionsToDelete": [{"Values": ["2026-01-01"]}, {"Values": ["missing"]}]})
        call("get-deleted-partition", "get-partition", {"DatabaseName": db, "TableName": "sales", "PartitionValues": ["2026-01-01"]})
        call("get-retained-partition", "get-partition", {"DatabaseName": db, "TableName": "sales", "PartitionValues": ["2026-01-02"]})
        call("batch-delete-tables-partial", "batch-delete-table", {"DatabaseName": db, "TablesToDelete": ["alpha", "missing"]})
        call("get-deleted-table", "get-table", {"DatabaseName": db, "Name": "alpha"})
        require(call("delete-last-partition", "delete-partition", {"DatabaseName": db, "TableName": "sales", "PartitionValues": ["2026-01-02"]}))
        for version in ("0", "2"):
            call("delete-version-" + version, "delete-table-version", {"DatabaseName": db, "TableName": "sales", "VersionId": version})
        require(call("delete-table", "delete-table", {"DatabaseName": db, "Name": "sales"}))
        call("get-table-after-delete", "get-table", {"DatabaseName": db, "Name": "sales"})
        call("get-partition-after-table-delete", "get-partition", {"DatabaseName": db, "TableName": "sales", "PartitionValues": ["2026-01-02"]})
        require(call("delete-database", "delete-database", {"Name": db}))
        call("delete-database-again", "delete-database", {"Name": db})
        call("get-tables-after-database-delete", "get-tables", {"DatabaseName": db})
        require(call("recreate-database", "create-database", {"DatabaseInput": {"Name": db}}))
        call("recreated-database-tables", "get-tables", {"DatabaseName": db})
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        if created:
            for name in ("alpha", "sales"):
                call("cleanup-table-" + name, "delete-table", {"DatabaseName": db, "Name": name})
            call("cleanup-database", "delete-database", {"Name": db})
            response = call("verify-database-absent", "get-database", {"Name": db})
            if response["code"] != "EntityNotFoundException":
                remaining.append(db)
        cap.finish(remaining)


if __name__ == "__main__":
    main()
