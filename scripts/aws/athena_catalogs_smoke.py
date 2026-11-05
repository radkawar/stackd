#!/usr/bin/env python3
"""Local-only Athena/Trino + Glue + managed S3 Tables interoperability.

Requires boto3, PyIceberg, PyArrow and a controller with -athena-runtime enabled.
Uses only explicit local fixture credentials. The Athena catalog name `iceberg`
 must be unused: this deliberately exercises a public/private connector collision.

Sources:
https://docs.aws.amazon.com/athena/latest/ug/gdc-register-s3-table-bucket-cat.html
https://docs.aws.amazon.com/lake-formation/latest/dg/create-databases-tables-s3-catalog.html
https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-tables-delete.html
"""
import argparse
import json
import time
import uuid
from urllib.parse import urlparse

import boto3
import pyarrow as pa
from botocore.config import Config
from botocore.exceptions import ClientError
from pyiceberg.catalog.rest import RestCatalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint-url", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    if urlparse(args.endpoint_url).hostname not in ("127.0.0.1", "localhost", "::1"):
        parser.error("an explicit loopback controller is required")
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=args.region)
    config = Config(retries={"max_attempts": 0}, s3={"addressing_style": "path"})
    clients = {name: session.client(name, endpoint_url=args.endpoint_url, config=config)
               for name in ("sts", "s3", "s3tables", "glue", "athena")}
    if clients["sts"].get_caller_identity()["Account"] != args.account:
        raise RuntimeError("explicit account differs from local STS")
    s3, tables, glue, athena = (clients[name] for name in ("s3", "s3tables", "glue", "athena"))
    suffix = uuid.uuid4().hex[:12]
    bucket, managed, database = "stackd-catalog-" + suffix, "stackd-managed-" + suffix, "catalog_" + suffix
    mounted = args.account + ":s3tablescatalog/" + managed
    created = {"bucket": False, "database": False, "parent": False, "catalog": False, "namespace": False}
    table_bucket, observations = None, []

    def query(sql, catalog="AwsDataCatalog", schema=None, success=True):
        query_id = athena.start_query_execution(QueryString=sql,
            QueryExecutionContext={"Catalog": catalog, "Database": schema or database},
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"})["QueryExecutionId"]
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            execution = athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
            state = execution["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                if (state == "SUCCEEDED") != success:
                    raise AssertionError(f"{sql}: {execution['Status']}")
                return query_id
            time.sleep(0.25)
        athena.stop_query_execution(QueryExecutionId=query_id)
        raise TimeoutError(sql)

    def rows(sql, catalog="AwsDataCatalog", schema=None):
        result = athena.get_query_results(QueryExecutionId=query(sql, catalog, schema))
        return [[cell.get("VarCharValue") for cell in row["Data"]] for row in result["ResultSet"]["Rows"]][1:]

    try:
        options = {} if args.region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": args.region}}
        s3.create_bucket(Bucket=bucket, **options)
        created["bucket"] = True
        glue.create_database(DatabaseInput={"Name": database})
        created["database"] = True
        s3.put_object(Bucket=bucket, Key="lookup/data.csv", Body=b"7,left\n9,unmatched\n")
        query(f"CREATE EXTERNAL TABLE lookup (id bigint, label string) ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE LOCATION 's3://{bucket}/lookup/'")
        table_bucket = tables.create_table_bucket(name=managed)["arn"]
        try:
            glue.get_catalog(CatalogId=args.account + ":s3tablescatalog")
        except glue.exceptions.EntityNotFoundException:
            glue.create_catalog(Name="s3tablescatalog", CatalogInput={"FederatedCatalog": {
                "ConnectionName": "aws:s3tables", "Identifier": f"arn:aws:s3tables:{args.region}:{args.account}:bucket/*"}})
            created["parent"] = True
        tables.create_namespace(tableBucketARN=table_bucket, namespace=["analytics"])
        created["namespace"] = True
        tables.create_table(tableBucketARN=table_bucket, namespace="analytics", name="events", format="ICEBERG",
            metadata={"iceberg": {"schema": {"fields": [{"name": "id", "type": "long"}, {"name": "label", "type": "string"}]}}})
        glue.create_table(CatalogId=mounted, DatabaseName="analytics", TableInput={"Name": "glue_created",
            "Parameters": {"format": "ICEBERG"}, "StorageDescriptor": {"Columns": [
                {"Name": "id", "Type": "bigint", "Parameters": {"required": "true"}}]}})
        tables.get_table(tableBucketARN=table_bucket, namespace="analytics", name="glue_created")
        athena.create_data_catalog(Name="iceberg", Type="GLUE", Parameters={"catalog-id": mounted})
        created["catalog"] = True
        query("INSERT INTO events VALUES (7, 'joined'), (8, 'other')", "iceberg", "analytics")
        query("INSERT INTO glue_created VALUES (31)", "iceberg", "analytics")
        assert rows("SELECT id FROM glue_created", "iceberg", "analytics") == [["31"]]
        joined = rows(f'SELECT t.id,t.label,r.label FROM "iceberg"."analytics"."events" t JOIN "awsdatacatalog"."{database}"."lookup" r ON t.id=r.id')
        assert joined == [["7", "joined", "left"]], joined
        observations.extend(["SDK and Glue create share managed owner", "native writes through registered GLUE source", "cross-catalog join and private connector name collision"])
        rest = RestCatalog("managed", **{
            "uri": args.endpoint_url + "/iceberg", "warehouse": mounted,
            "rest.sigv4-enabled": "true", "rest.signing-name": "glue", "rest.signing-region": args.region,
            "client.region": args.region, "client.access-key-id": "test", "client.secret-access-key": "test",
            "s3.endpoint": args.endpoint_url, "s3.region": args.region,
            "s3.access-key-id": "test", "s3.secret-access-key": "test",
            "s3.force-virtual-addressing": "false", "py-io-impl": "pyiceberg.io.pyarrow.PyArrowFileIO"})
        native = rest.load_table(("analytics", "events"))
        assert sorted(native.scan().to_arrow().to_pylist(), key=lambda row: row["id"]) == [{"id": 7, "label": "joined"}, {"id": 8, "label": "other"}]
        native.append(pa.table({"id": pa.array([10], type=pa.int64()), "label": pa.array(["rest"], type=pa.string())}))
        with native.update_schema() as update:
            update.rename_column("label", "message")
        assert rows("SELECT id,message FROM events ORDER BY id", "iceberg", "analytics") == [["7", "joined"], ["8", "other"], ["10", "rest"]]
        projected = glue.get_table(CatalogId=mounted, DatabaseName="analytics", Name="events")["Table"]["StorageDescriptor"]["Columns"]
        assert [(column["Name"], column["Type"]) for column in projected] == [("id", "bigint"), ("message", "string")], projected
        described = athena.get_table_metadata(CatalogName="iceberg", DatabaseName="analytics", TableName="events")["TableMetadata"]["Columns"]
        assert [(column["Name"], column["Type"]) for column in described] == [("id", "bigint"), ("message", "string")], described
        observations.append("PyIceberg native read/append/schema evolution visible in Trino and metadata APIs")
        location = urlparse(native.metadata_location)
        rest.purge_table(("analytics", "events"))
        try:
            s3.get_object(Bucket=location.netloc, Key=location.path.lstrip("/"))
        except ClientError as error:
            assert error.response["ResponseMetadata"]["HTTPStatusCode"] in (403, 404), error
        else:
            raise AssertionError("managed deleted warehouse remained readable")
        observations.append("managed REST purge removes table authority without ordinary S3 fallback")
        print(json.dumps({"completed": True, "observations": observations}, indent=2))
    finally:
        failures = []
        def cleanup(label, action):
            try:
                action()
            except Exception as error:
                failures.append(f"{label}: {error}")
        if created["catalog"]:
            cleanup("Athena catalog", lambda: athena.delete_data_catalog(Name="iceberg"))
        if created["namespace"]:
            def remove_tables():
                for page in tables.get_paginator("list_tables").paginate(tableBucketARN=table_bucket, namespace="analytics"):
                    for table in page["tables"]:
                        tables.delete_table(tableBucketARN=table_bucket, namespace="analytics", name=table["name"])
            cleanup("managed tables", remove_tables)
            cleanup("managed namespace", lambda: tables.delete_namespace(tableBucketARN=table_bucket, namespace="analytics"))
        if table_bucket:
            cleanup("managed bucket", lambda: tables.delete_table_bucket(tableBucketARN=table_bucket))
        if created["parent"]:
            cleanup("Glue integration", lambda: glue.delete_catalog(CatalogId=args.account + ":s3tablescatalog"))
        if created["database"]:
            cleanup("Glue database", lambda: glue.delete_database(Name=database))
        if created["bucket"]:
            def remove_objects():
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                    for obj in page.get("Contents", []):
                        s3.delete_object(Bucket=bucket, Key=obj["Key"])
                s3.delete_bucket(Bucket=bucket)
            cleanup("ordinary bucket", remove_objects)
        if failures:
            raise RuntimeError("Owned cleanup failed: " + "; ".join(failures))


if __name__ == "__main__":
    main()
