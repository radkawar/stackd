#!/usr/bin/env python3
"""Exercise actual Spark-parser/Trino/Glue/S3 Athena semantics on a local controller.

Prerequisites: boto3, pyarrow, explicitly installed pinned engine images, controller with
-athena-runtime enabled and local fixture credentials. No real AWS endpoint is
used or inferred. Example (obtain the account with the local STS CLI first):
  python3 scripts/aws/athena_hive_semantics_smoke.py \
    --endpoint-url http://127.0.0.1:4566 --account 123456789012
Run parser proof separately:
  STACKD_ATHENA_NETWORK_DOCKER_HOST=unix:///var/run/docker.sock \
    go test ./engine/athena -run 'TestHiveDDLNativeFamilies|TestCTASParserNative' -v

Supported AWS grammar under test: ALTER DATABASE SET DBPROPERTIES; ALTER TABLE
[PARTITION (...)] ADD COLUMNS, CHANGE [COLUMN] old new type [COMMENT]
[FIRST|AFTER], [PARTITION (...)] REPLACE COLUMNS, ADD [IF NOT EXISTS] PARTITION
[(LOCATION)], DROP [IF EXISTS] PARTITION, PARTITION RENAME TO PARTITION,
[PARTITION] SET LOCATION and SET TBLPROPERTIES; additive MSCK REPAIR TABLE;
CREATE [OR REPLACE] VIEW AS SELECT, SELECT/SHOW CREATE/DROP VIEW; external Hive
CLUSTERED BY ... INTO n BUCKETS; Iceberg bucket(N,column), truncate(L,column),
year/month/day/hour transforms; CTAS native properties translated by pinned
Trino AST. Unsupported Spark-only USING/constraints, invalid syntax/properties
and current denied source access must fail, never mutate metadata as success.

Sources:
https://docs.aws.amazon.com/athena/latest/ug/ddl-reference.html
https://docs.aws.amazon.com/athena/latest/ug/alter-table-change-column.html
https://docs.aws.amazon.com/athena/latest/ug/alter-table-replace-columns.html
https://docs.aws.amazon.com/athena/latest/ug/msck-repair-table.html
https://docs.aws.amazon.com/athena/latest/ug/create-view.html
https://docs.aws.amazon.com/athena/latest/ug/create-table-as.html
https://docs.aws.amazon.com/athena/latest/ug/querying-iceberg-creating-tables.html
https://trino.io/docs/476/connector/hive.html
https://trino.io/docs/476/connector/iceberg.html
https://github.com/apache/spark/blob/v4.1.3/sql/catalyst/src/main/scala/org/apache/spark/sql/catalyst/parser/AstBuilder.scala
"""
import argparse
import io
import json
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse

import boto3
import pyarrow.parquet as parquet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint-url", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    endpoint = urlparse(args.endpoint_url)
    if endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
        parser.error("this fixture only targets an explicitly selected loopback controller")
    session = boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=args.region)
    clients = {service: session.client(service, endpoint_url=args.endpoint_url) for service in ("sts", "s3", "glue", "athena")}
    if clients["sts"].get_caller_identity()["Account"] != args.account:
        raise RuntimeError("explicit account does not match local STS")
    s3, glue, athena = (clients[name] for name in ("s3", "glue", "athena"))
    suffix = uuid.uuid4().hex[:16]
    bucket, database = "stackd-hive-" + suffix, "stackd_hive_" + suffix
    regular_group, enforced_group = "stackd-hive-regular-" + suffix, "stackd-hive-enforced-" + suffix
    observations, created = [], {"bucket": False, "database": False, "groups": []}

    def query(sql, success=True, group=None):
        response = athena.start_query_execution(QueryString=sql,
            WorkGroup=group or regular_group,
            QueryExecutionContext={"Catalog": "AwsDataCatalog", "Database": database},
            ResultConfiguration={"OutputLocation": f"s3://{bucket}/results/"})
        query_id = response["QueryExecutionId"]
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            execution = athena.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
            state = execution["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                status = {key: value.isoformat() if isinstance(value, datetime) else value
                          for key, value in execution["Status"].items()}
                observations.append({"sql": sql, "status": status, "statistics": execution.get("Statistics", {})})
                if (state == "SUCCEEDED") != success:
                    raise AssertionError(f"Unexpected SQL outcome: {sql}: {execution['Status']}")
                return query_id
            time.sleep(0.25)
        athena.stop_query_execution(QueryExecutionId=query_id)
        raise RuntimeError("query timed out: " + sql)

    def rows(sql):
        result = athena.get_query_results(QueryExecutionId=query(sql))
        return [[cell.get("VarCharValue") for cell in row["Data"]] for row in result["ResultSet"]["Rows"]][1:]

    try:
        options = {} if args.region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": args.region}}
        s3.create_bucket(Bucket=bucket, **options)
        created["bucket"] = True
        glue.create_database(DatabaseInput={"Name": database})
        created["database"] = True
        for group, enforced in ((regular_group, False), (enforced_group, True)):
            athena.create_work_group(Name=group, Configuration={
                "EnforceWorkGroupConfiguration": enforced,
                "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/enforced/"},
            })
            created["groups"].append(group)
        s3.put_object(Bucket=bucket, Key="events/day=2026-01-01/data.txt", Body=b"1\n2\n")
        query(f"CREATE EXTERNAL TABLE events (id bigint) PARTITIONED BY (day string) STORED AS TEXTFILE LOCATION 's3://{bucket}/events/'")
        query("MSCK REPAIR TABLE events")
        assert rows("SELECT count(*) AS n FROM events") == [["2"]]
        query("MSCK REPAIR TABLE events")
        assert len(glue.get_partitions(DatabaseName=database, TableName="events")["Partitions"]) == 1
        literal_root = "literal%2F root/雪/"
        literal_partitions = {"us/east": "us%2Feast", "space value": "space value",
                              "雪": "雪", "__HIVE_DEFAULT_PARTITION__": "__HIVE_DEFAULT_PARTITION__"}
        for index, path in enumerate(literal_partitions.values(), start=1):
            s3.put_object(Bucket=bucket, Key=literal_root + "day=" + path + "/data.txt",
                          Body=f"{index}\n".encode())
        query(f"CREATE EXTERNAL TABLE literal_paths (id bigint) PARTITIONED BY (day string) STORED AS TEXTFILE LOCATION 's3://{bucket}/{literal_root}'")
        query("MSCK REPAIR TABLE literal_paths")
        query("MSCK REPAIR TABLE literal_paths")
        actual = glue.get_partitions(DatabaseName=database, TableName="literal_paths")["Partitions"]
        assert len(actual) == 4
        for partition in actual:
            expected_path = literal_root + "day=" + literal_partitions[partition["Values"][0]] + "/"
            assert partition["StorageDescriptor"]["Location"] == f"s3://{bucket}/{expected_path}"
        assert rows("SELECT id FROM literal_paths ORDER BY id") == [["1"], ["2"], ["3"], ["4"]]
        sentinel_filter = glue.get_partitions(DatabaseName=database, TableName="literal_paths",
            Expression="(day = '__HIVE_DEFAULT_PARTITION__')")["Partitions"]
        assert [partition["Values"] for partition in sentinel_filter] == [["__HIVE_DEFAULT_PARTITION__"]], (
            "Glue sentinel equality did not select the stored string", sentinel_filter)
        api_null_filter = glue.get_partitions(DatabaseName=database, TableName="literal_paths",
            Expression="day IS NULL")["Partitions"]
        assert not api_null_filter, ("Glue metadata strings were coerced into SQL NULL", api_null_filter)
        null_rows = rows("SELECT id FROM literal_paths WHERE day IS NULL")
        assert null_rows == [["4"]], ("Native Hive NULL partition rows", null_rows,
                                     "Glue partitions", [partition["Values"] for partition in actual])
        nonnull_rows = rows("SELECT id FROM literal_paths WHERE day IS NOT NULL ORDER BY id")
        assert nonnull_rows == [["1"], ["2"], ["3"]], ("Native non-NULL partition rows", nonnull_rows)
        mixed_rows = rows("SELECT id FROM literal_paths WHERE day IS NULL OR day='us/east' ORDER BY id")
        assert mixed_rows == [["1"], ["4"]], ("Native nullable disjunction rows", mixed_rows)
        query("ALTER DATABASE " + database + " SET DBPROPERTIES ('fixture'='native')")
        query("ALTER TABLE events SET TBLPROPERTIES ('fixture'='updated')")
        query("ALTER TABLE events ADD COLUMNS (payload string)")
        query("ALTER TABLE events CHANGE COLUMN payload renamed string COMMENT 'native' AFTER id")
        query("ALTER TABLE events REPLACE COLUMNS (id bigint)")
        query(f"ALTER TABLE events ADD IF NOT EXISTS PARTITION (DAY='manual') LOCATION 's3://{bucket}/manual/'")
        query("ALTER TABLE events PARTITION (dAy='manual') ADD COLUMNS (local_payload string)")
        query("ALTER TABLE events PARTITION (DAY='manual') RENAME TO PARTITION (Day='renamed')")
        query("ALTER TABLE events PARTITION (DAY='renamed') REPLACE COLUMNS (id bigint)")
        query(f"ALTER TABLE events PARTITION (dAy='renamed') SET LOCATION 's3://{bucket}/moved/'")
        query("ALTER TABLE events DROP PARTITION (DAY='renamed')")
        query("ALTER TABLE events DROP IF EXISTS PARTITION (dAy='renamed')")
        query("ALTER TABLE events ADD PARTITION (day='a', DAY='b')", success=False)
        query("CREATE VIEW event_view AS SELECT id, day FROM events")
        assert rows("SELECT count(*) AS n FROM event_view") == [["2"]]
        query("CREATE OR REPLACE VIEW event_view AS SELECT id FROM events WHERE id=2")
        assert rows("SELECT id FROM event_view") == [["2"]]
        assert rows("SHOW CREATE VIEW event_view")
        query("DROP VIEW event_view")
        query("SELECT * FROM event_view", success=False)
        query(f"CREATE TABLE bucketed WITH (format='PARQUET', external_location='s3://{bucket}/bucketed/', bucketed_by=ARRAY['id'], bucket_count=4, write_compression='SNAPPY') AS SELECT id FROM events")
        assert rows("SELECT count(*) AS n FROM bucketed") == [["2"]]
        metadata = glue.get_table(DatabaseName=database, Name="bucketed")["Table"]["StorageDescriptor"]
        assert metadata["NumberOfBuckets"] == 4 and metadata["BucketColumns"] == ["id"]
        objects = s3.list_objects_v2(Bucket=bucket, Prefix="bucketed/").get("Contents", [])
        assert objects
        verified_files = 0
        for item in objects:
            body = s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read()
            if body.startswith(b"PAR1"):
                native_file = parquet.ParquetFile(io.BytesIO(body))
                for group in range(native_file.metadata.num_row_groups):
                    assert native_file.metadata.row_group(group).column(0).compression == "SNAPPY"
                verified_files += 1
        assert verified_files
        query(f"CREATE EXTERNAL TABLE declared_buckets (id bigint) CLUSTERED BY (id) INTO 4 BUCKETS STORED AS PARQUET LOCATION 's3://{bucket}/declared/'")
        query(f"CREATE TABLE transformed (ID bigint, Created_At timestamp) PARTITIONED BY (bucket(4,Id),day(CREATED_AT)) LOCATION 's3://{bucket}/transformed/' TBLPROPERTIES ('table_type'='ICEBERG')")
        query("INSERT INTO transformed VALUES (1,TIMESTAMP '2026-01-01 00:00:00')")
        assert rows("SELECT id FROM transformed") == [["1"]]
        query(f"CREATE TABLE identity_mixed (ID bigint) PARTITIONED BY (Id) LOCATION 's3://{bucket}/identity-mixed/' TBLPROPERTIES ('table_type'='ICEBERG')")
        query("INSERT INTO identity_mixed VALUES (7)")
        assert rows("SELECT id FROM identity_mixed") == [["7"]]
        forbidden = f"s3://{bucket}/forbidden-ctas/"
        query(f"CREATE TABLE enforced_rejected WITH (external_location='{forbidden}') AS SELECT 1 id",
              success=False, group=enforced_group)
        assert not s3.list_objects_v2(Bucket=bucket, Prefix="forbidden-ctas/").get("Contents")
        try:
            glue.get_table(DatabaseName=database, Name="enforced_rejected")
        except glue.exceptions.EntityNotFoundException:
            pass
        else:
            raise AssertionError("Rejected CTAS created Glue table")
        enforced_id = query("CREATE TABLE enforced_default AS SELECT 11 id", group=enforced_group)
        location = glue.get_table(DatabaseName=database, Name="enforced_default")["Table"]["StorageDescriptor"]["Location"]
        assert location.rstrip("/") == f"s3://{bucket}/enforced/tables/{enforced_id}"
        assert s3.list_objects_v2(Bucket=bucket, Prefix=f"enforced/tables/{enforced_id}/").get("Contents")
        assert rows("SELECT id FROM enforced_default") == [["11"]]
        query("CREATE TABLE invalid_ctas WITH (format='PARQUET', write_compression='SNAPPY', parquet_compression='GZIP') AS SELECT 1 AS id", success=False)
        query("ALTER TABLE events ADD COLUMNS (id bigint)", success=False)
        query("ALTER TABLE events ADD PARTITION (", success=False)
        query(f"CREATE TABLE unsupported_using (id bigint) USING parquet LOCATION 's3://{bucket}/unsupported/'", success=False)
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}/events/*", f"arn:aws:s3:::{bucket}"]}]}))
        query("SELECT * FROM events", success=False)
        query("MSCK REPAIR TABLE events", success=False)
        query(f"CREATE TABLE denied_ctas WITH (external_location='s3://{bucket}/denied/') AS SELECT * FROM events", success=False)
        s3.delete_bucket_policy(Bucket=bucket)
        assert rows("SELECT count(*) AS n FROM events") == [["2"]]
        print(json.dumps({"observations": observations, "completed": True}, indent=2))
    finally:
        cleanup_errors = []
        for group in created["groups"]:
            try:
                athena.delete_work_group(WorkGroup=group, RecursiveDeleteOption=True)
            except Exception as error:
                cleanup_errors.append(str(error))
        if created["bucket"]:
            try:
                s3.delete_bucket_policy(Bucket=bucket)
            except Exception as error:
                cleanup_errors.append(str(error))
        if created["database"]:
            try:
                for page in glue.get_paginator("get_tables").paginate(DatabaseName=database):
                    for table in page["TableList"]:
                        glue.delete_table(DatabaseName=database, Name=table["Name"])
                glue.delete_database(Name=database)
            except Exception as error:
                cleanup_errors.append(str(error))
        if created["bucket"]:
            try:
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
                    objects = [{"Key": item["Key"]} for item in page.get("Contents", [])]
                    if objects:
                        result = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                        if result.get("Errors"):
                            raise RuntimeError(str(result["Errors"]))
                s3.delete_bucket(Bucket=bucket)
            except Exception as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise RuntimeError("owned fixture cleanup failed: " + "; ".join(cleanup_errors))


if __name__ == "__main__":
    main()
